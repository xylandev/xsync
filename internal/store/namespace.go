package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

func (s *Store) Current(tenant, name string) (model.ObjectVersion, error) {
	clean, err := CleanPath(name)
	if err != nil {
		return model.ObjectVersion{}, err
	}
	var o model.ObjectVersion
	err = s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bNamespace).Get(nsKey(tenant, clean))
		if id == nil {
			return ErrNotFound
		}
		var e error
		o, e = getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
		return e
	})
	return o, err
}

func (s *Store) OpenCurrent(tenant, name string) (*os.File, model.ObjectVersion, error) {
	o, err := s.Current(tenant, name)
	if err != nil {
		return nil, o, err
	}
	f, err := os.Open(o.BlobPath)
	return f, o, err
}

// FileInfo is what an uploader sees at a path.
type FileInfo struct {
	Path      string
	Size      int64
	ModTime   time.Time
	Directory bool
	// Partial marks an interrupted upload that has not been published; its
	// size is where a resuming client must continue.
	Partial bool
}

// Stat describes a path the way the uploader should see it. An interrupted
// upload newer than the published version is reported with its partial size,
// so a client that resumes from the reported size continues exactly the
// bytes the server kept.
func (s *Store) Stat(tenant, name string) (FileInfo, error) {
	clean, err := CleanPath(name)
	if err != nil {
		return FileInfo{}, err
	}
	if clean == "" {
		return FileInfo{Path: "", Directory: true, ModTime: s.now()}, nil
	}
	var info FileInfo
	err = s.db.View(func(tx *bolt.Tx) error {
		var cur *model.ObjectVersion
		if id := tx.Bucket(bNamespace).Get(nsKey(tenant, clean)); id != nil {
			if o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id); e == nil {
				cur = &o
			}
		}
		if u, e := newestInterrupted(tx, tenant, clean); e == nil && (cur == nil || u.UpdatedAt.After(cur.CreatedAt)) {
			if st, e := os.Stat(u.StagingPath); e == nil {
				info = FileInfo{Path: clean, Size: st.Size(), ModTime: u.UpdatedAt, Partial: true}
				return nil
			}
		}
		if cur != nil {
			info = FileInfo{Path: clean, Size: cur.Size, ModTime: cur.CreatedAt}
			return nil
		}
		if tx.Bucket(bDirectories).Get(nsKey(tenant, clean)) != nil || hasChildren(tx, tenant, clean) {
			info = FileInfo{Path: clean, Directory: true, ModTime: s.now()}
			return nil
		}
		return ErrNotFound
	})
	return info, err
}

// Remove deletes the object at name. An object being delivered is detached
// from the path and deleted once its lease ends without a commit.
func (s *Store) Remove(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	var victim *model.ObjectVersion
	err = s.update(func(tx *bolt.Tx, d *delta) error {
		victim = nil
		key := nsKey(tenant, clean)
		id := bytes.Clone(tx.Bucket(bNamespace).Get(key))
		if id == nil {
			if tx.Bucket(bDirectories).Get(key) != nil || hasChildren(tx, tenant, clean) {
				return ErrIsDirectory
			}
			return ErrNotFound
		}
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
		if err != nil {
			return tx.Bucket(bNamespace).Delete(key)
		}
		if o.State == model.StateLeased {
			o.Retracted = true
			if err := tx.Bucket(bNamespace).Delete(key); err != nil {
				return err
			}
			return putJSON(tx.Bucket(bObjects), id, o)
		}
		victim = &o
		return s.deleteObjectTx(tx, d, o, "removed")
	})
	if err == nil && victim != nil {
		s.collect(victim.ID, victim.Tenant, victim.BlobPath, victim.Size)
	}
	return err
}

// Rename moves a file or directory. With overwrite (POSIX rename semantics) an
// existing destination file is replaced under the tenant's overwrite policy.
// Renaming a held temporary file to its final name releases it for delivery.
func (s *Store) Rename(tenant, oldName, newName string) error {
	return s.RenameWith(tenant, oldName, newName, false)
}

func (s *Store) RenameWith(tenant, oldName, newName string, overwrite bool) error {
	oldPath, err := CleanPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := CleanPath(newName)
	if err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}
	if newPath == "" {
		return errors.New("invalid destination: empty path")
	}
	if oldPath == "" {
		return fmt.Errorf("%w: cannot rename the root", ErrInvalidPath)
	}
	pol := s.policyFor(tenant)
	var victims []model.ObjectVersion
	err = s.update(func(tx *bolt.Tx, d *delta) error {
		victims = victims[:0]
		id := tx.Bucket(bNamespace).Get(nsKey(tenant, oldPath))
		if oldPath == newPath {
			return renameInPlace(tx, tenant, oldPath, id != nil)
		}
		if id != nil {
			return s.renameFile(tx, d, tenant, oldPath, newPath, bytes.Clone(id), overwrite, pol, &victims)
		}
		return s.renameTree(tx, d, tenant, oldPath, newPath, pol)
	})
	for _, v := range victims {
		s.collect(v.ID, v.Tenant, v.BlobPath, v.Size)
	}
	return err
}

// renameInPlace resolves a rename onto the same path: it succeeds when the path
// exists as a file, as a directory, or as the parent of something.
func renameInPlace(tx *bolt.Tx, tenant, path string, isFile bool) error {
	if isFile || tx.Bucket(bDirectories).Get(nsKey(tenant, path)) != nil || hasChildren(tx, tenant, path) {
		return nil
	}
	return ErrNotFound
}

// hasChildren reports whether any file or directory lives under path.
func hasChildren(tx *bolt.Tx, tenant, path string) bool {
	prefix := nsKey(tenant, path+"/")
	for _, b := range []*bolt.Bucket{tx.Bucket(bNamespace), tx.Bucket(bDirectories)} {
		if k, _ := b.Cursor().Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func (s *Store) renameFile(tx *bolt.Tx, d *delta, tenant, oldPath, newPath string, id []byte, overwrite bool, pol Policy, victims *[]model.ObjectVersion) error {
	objects := tx.Bucket(bObjects)
	o, err := getJSON[model.ObjectVersion](objects, id)
	if err != nil {
		return err
	}
	if o.State == model.StateLeased {
		return ErrBusy
	}
	key := nsKey(tenant, newPath)
	if tx.Bucket(bDirectories).Get(key) != nil || hasChildren(tx, tenant, newPath) {
		return ErrConflict
	}
	if err := checkAncestors(tx, tenant, newPath); err != nil {
		return err
	}
	if destID := tx.Bucket(bNamespace).Get(key); destID != nil {
		if !overwrite {
			return ErrConflict
		}
		victim, err := s.replacePath(tx, d, tenant, newPath, pol.Supersede, "superseded")
		if err != nil {
			return err
		}
		if victim != nil {
			*victims = append(*victims, *victim)
		}
	}
	if err := s.moveObject(tx, d, &o, newPath, pol); err != nil {
		return err
	}
	ns := tx.Bucket(bNamespace)
	if err := ns.Put(key, id); err != nil {
		return err
	}
	return ns.Delete(nsKey(tenant, oldPath))
}

// moveObject changes an object's path, keeping its queue position, and
// reclassifies it when the rename crosses a hold pattern.
func (s *Store) moveObject(tx *bolt.Tx, d *delta, o *model.ObjectVersion, newPath string, pol Policy) error {
	now := s.now().UTC()
	wasQueued := o.QueueSeq != 0
	seq, visible := o.QueueSeq, o.VisibleAt
	if err := dequeue(tx, o); err != nil {
		return err
	}
	o.Path, o.UpdatedAt = newPath, now
	nowHeld := Held(pol.HoldPatterns, newPath)
	switch {
	case o.State == model.StateHeld && !nowHeld:
		if err := tx.Bucket(bHeld).Delete(timeIDKey(o.CreatedAt, o.ID)); err != nil {
			return err
		}
		return s.place(tx, d, o, model.StateHeld, pol, now)
	case o.State == model.StateReady && nowHeld:
		return s.place(tx, d, o, model.StateReady, pol, now)
	case wasQueued:
		o.QueueSeq, o.VisibleAt = seq, visible
		if err := putQueueEntries(tx, o); err != nil {
			return err
		}
	}
	return putJSON(tx.Bucket(bObjects), []byte(o.ID), *o)
}

func (s *Store) renameTree(tx *bolt.Tx, d *delta, tenant, oldPath, newPath string, pol Policy) error {
	if strings.HasPrefix(newPath, oldPath+"/") {
		return ErrConflict
	}
	key := nsKey(tenant, newPath)
	if tx.Bucket(bNamespace).Get(key) != nil || tx.Bucket(bDirectories).Get(key) != nil || hasChildren(tx, tenant, newPath) {
		return ErrConflict
	}
	if err := checkAncestors(tx, tenant, newPath); err != nil {
		return err
	}
	moves := collectTreeMoves(tx, tenant, oldPath, newPath)
	if len(moves) == 0 {
		return ErrNotFound
	}
	objects := tx.Bucket(bObjects)
	for _, m := range moves {
		if m.directory {
			continue
		}
		if o, err := getJSON[model.ObjectVersion](objects, m.objectID); err == nil && o.State == model.StateLeased {
			return ErrBusy
		}
	}
	for _, m := range moves {
		if err := s.applyTreeMove(tx, d, tenant, m, pol); err != nil {
			return err
		}
	}
	return nil
}

// treeMove is one namespace or directory key relocated by a directory rename.
type treeMove struct {
	oldKey, newKey []byte
	objectID       []byte
	directory      bool
}

// collectTreeMoves snapshots the keys to relocate before any of them is written,
// because a bucket must not be mutated while a cursor is walking it.
func collectTreeMoves(tx *bolt.Tx, tenant, oldPath, newPath string) []treeMove {
	var moves []treeMove
	ns, dirs := tx.Bucket(bNamespace), tx.Bucket(bDirectories)
	filePrefix := nsKey(tenant, oldPath+"/")
	c := ns.Cursor()
	for k, v := c.Seek(filePrefix); k != nil && bytes.HasPrefix(k, filePrefix); k, v = c.Next() {
		suffix := strings.TrimPrefix(string(k), string(filePrefix))
		moves = append(moves, treeMove{oldKey: bytes.Clone(k), newKey: nsKey(tenant, newPath+"/"+suffix), objectID: bytes.Clone(v)})
	}
	// The directory itself plus every directory under it.
	dirKey := nsKey(tenant, oldPath)
	dirPrefix := append(bytes.Clone(dirKey), '/')
	dc := dirs.Cursor()
	for k, _ := dc.Seek(dirKey); k != nil && (bytes.Equal(k, dirKey) || bytes.HasPrefix(k, dirPrefix)); k, _ = dc.Next() {
		suffix := strings.TrimPrefix(strings.TrimPrefix(string(k), tenant+"\x00"), oldPath)
		moves = append(moves, treeMove{oldKey: bytes.Clone(k), newKey: nsKey(tenant, newPath+suffix), directory: true})
	}
	return moves
}

func (s *Store) applyTreeMove(tx *bolt.Tx, d *delta, tenant string, m treeMove, pol Policy) error {
	newPath := strings.TrimPrefix(string(m.newKey), tenant+"\x00")
	if m.directory {
		dirs := tx.Bucket(bDirectories)
		if err := putJSON(dirs, m.newKey, model.Entry{Path: newPath, Directory: true, UpdatedAt: s.now().UTC()}); err != nil {
			return err
		}
		return dirs.Delete(m.oldKey)
	}
	o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), m.objectID)
	if err != nil {
		return err
	}
	if err := s.moveObject(tx, d, &o, newPath, pol); err != nil {
		return err
	}
	ns := tx.Bucket(bNamespace)
	if err := ns.Put(m.newKey, m.objectID); err != nil {
		return err
	}
	return ns.Delete(m.oldKey)
}

func (s *Store) DirectoryExists(tenant, name string) (bool, error) {
	clean, err := CleanPath(name)
	if err != nil {
		return false, err
	}
	if clean == "" {
		return true, nil
	}
	exists := false
	err = s.db.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bDirectories).Get(nsKey(tenant, clean)) != nil || hasChildren(tx, tenant, clean)
		return nil
	})
	return exists, err
}

func (s *Store) RemoveDir(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	if clean == "" {
		return ErrConflict
	}
	return s.update(func(tx *bolt.Tx, _ *delta) error {
		if hasChildren(tx, tenant, clean) {
			return ErrConflict
		}
		key := nsKey(tenant, clean)
		if tx.Bucket(bDirectories).Get(key) == nil {
			return ErrNotFound
		}
		return tx.Bucket(bDirectories).Delete(key)
	})
}

// Mkdir creates a directory entry. A file of the same name, or a file among
// its parents, is a conflict: the namespace never holds both.
func (s *Store) Mkdir(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	if clean == "" {
		return nil
	}
	e := model.Entry{Path: clean, Directory: true, UpdatedAt: s.now().UTC()}
	return s.update(func(tx *bolt.Tx, _ *delta) error {
		if tx.Bucket(bNamespace).Get(nsKey(tenant, clean)) != nil {
			return ErrConflict
		}
		if err := checkAncestors(tx, tenant, clean); err != nil {
			return err
		}
		return putJSON(tx.Bucket(bDirectories), nsKey(tenant, clean), e)
	})
}

type ListedEntry struct {
	Path      string
	Object    *model.ObjectVersion
	Directory bool
}

func (s *Store) List(tenant, dir string) ([]ListedEntry, error) {
	clean, err := CleanPath(dir)
	if err != nil {
		return nil, err
	}
	prefix := clean
	if prefix != "" {
		prefix += "/"
	}
	entries := map[string]ListedEntry{}
	err = s.db.View(func(tx *bolt.Tx) error {
		ns := tx.Bucket(bNamespace)
		seek := nsKey(tenant, prefix)
		c := ns.Cursor()
		for k, id := c.Seek(seek); k != nil && bytes.HasPrefix(k, seek); {
			full := strings.TrimPrefix(string(k), tenant+"\x00")
			rest := strings.TrimPrefix(full, prefix)
			if rest == "" {
				k, id = c.Next()
				continue
			}
			part, _, nested := strings.Cut(rest, "/")
			if nested {
				entries[part] = ListedEntry{Path: prefix + part, Directory: true}
				// Skip the whole subtree instead of walking it.
				k, id = c.Seek(nsKey(tenant, prefix+part+"/\xff"))
				continue
			}
			if o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id); e == nil {
				oo := o
				entries[part] = ListedEntry{Path: full, Object: &oo}
			}
			k, id = c.Next()
		}
		dc := tx.Bucket(bDirectories).Cursor()
		for k, _ := dc.Seek(seek); k != nil && bytes.HasPrefix(k, seek); k, _ = dc.Next() {
			rest := strings.TrimPrefix(strings.TrimPrefix(string(k), tenant+"\x00"), prefix)
			if rest == "" {
				continue
			}
			part, _, _ := strings.Cut(rest, "/")
			if _, ok := entries[part]; !ok {
				entries[part] = ListedEntry{Path: prefix + part, Directory: true}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]ListedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// ListPage is one page of an S3-style listing.
type ListPage struct {
	Objects        []model.ObjectVersion
	CommonPrefixes []string
	Truncated      bool
	NextAfter      string
}

// ListKeys lists a tenant's published keys in byte order, starting strictly
// after startAfter, folding keys at delimiter like S3. It walks only the keys
// it returns (plus one to detect truncation), so every page costs the same
// regardless of how many objects the tenant holds.
func (s *Store) ListKeys(tenant, prefix, delimiter, startAfter string, limit int) (ListPage, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var page ListPage
	err := s.db.View(func(tx *bolt.Tx) error {
		page = ListPage{}
		base := []byte(tenant + "\x00")
		seek := append(bytes.Clone(base), prefix...)
		if startAfter > prefix {
			seek = append(bytes.Clone(base), startAfter...)
		}
		c := tx.Bucket(bNamespace).Cursor()
		count := 0
		for k, id := c.Seek(seek); k != nil && bytes.HasPrefix(k, base); {
			key := string(k[len(base):])
			if !strings.HasPrefix(key, prefix) {
				break
			}
			entry, isPrefix := key, false
			if delimiter != "" {
				if i := strings.Index(key[len(prefix):], delimiter); i >= 0 {
					entry, isPrefix = key[:len(prefix)+i+len(delimiter)], true
				}
			}
			if entry <= startAfter {
				if isPrefix {
					k, id = c.Seek(append(append(bytes.Clone(base), entry...), 0xff))
				} else {
					k, id = c.Next()
				}
				continue
			}
			if count == limit {
				page.Truncated = true
				break
			}
			count++
			page.NextAfter = entry
			if isPrefix {
				page.CommonPrefixes = append(page.CommonPrefixes, entry)
				k, id = c.Seek(append(append(bytes.Clone(base), entry...), 0xff))
				continue
			}
			if o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id); e == nil {
				page.Objects = append(page.Objects, o)
			}
			k, id = c.Next()
		}
		return nil
	})
	return page, err
}

// ListAll returns every published object under prefix. It is meant for small
// listings and tests; S3 uses ListKeys.
func (s *Store) ListAll(tenant, prefix string) ([]model.ObjectVersion, error) {
	var out []model.ObjectVersion
	after := ""
	for {
		page, err := s.ListKeys(tenant, prefix, "", after, 1000)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Objects...)
		if !page.Truncated {
			return out, nil
		}
		after = page.NextAfter
	}
}
