package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrLeaseMismatch = errors.New("lease mismatch")
	ErrConflict      = errors.New("conflict")
	ErrInsufficient  = errors.New("insufficient storage")
	ErrUploadBlocked = errors.New("new uploads are temporarily blocked")
)

var (
	bObjects     = []byte("objects")
	bNamespace   = []byte("namespace")
	bQueue       = []byte("queue")
	bClaims      = []byte("claims")
	bUploads     = []byte("uploads")
	bTombstones  = []byte("tombstones")
	bVersions    = []byte("versions")
	bDirectories = []byte("directories")
)

type UploadGate interface {
	AllowNewUpload() bool
	WaitN(context.Context, string, int) error
	AcquireUpload(context.Context, string) (func(), error)
}

type Store struct {
	root string
	db   *bolt.DB
	gate UploadGate
	now  func() time.Time
	mu   sync.RWMutex
}

func Open(root string, gate UploadGate) (*Store, error) {
	for _, dir := range []string{"staging", "objects", "metadata"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(filepath.Join(root, "metadata", "catalog.db"), 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, db: db, gate: gate, now: time.Now}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bObjects, bNamespace, bQueue, bClaims, bUploads, bTombstones, bVersions, bDirectories} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.Recover(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error         { return s.db.Close() }
func (s *Store) Root() string         { return s.root }
func (s *Store) AllowNewUpload() bool { return s.gate == nil || s.gate.AllowNewUpload() }
func (s *Store) WaitUpload(ctx context.Context, tenant string, n int) error {
	if s.gate == nil {
		return nil
	}
	return s.gate.WaitN(ctx, tenant, n)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, raw)
}

func getJSON[T any](b *bolt.Bucket, key []byte) (T, error) {
	var out T
	raw := b.Get(key)
	if raw == nil {
		return out, ErrNotFound
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

type UploadHandle struct {
	store   *Store
	upload  model.Upload
	file    *os.File
	closed  bool
	failed  error
	ctx     context.Context
	mu      sync.Mutex
	release func()
}

func (s *Store) BeginUpload(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	return s.beginUpload(ctx, tenant, name, protocol, false)
}

func (s *Store) BeginUploadFromCurrent(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	clean, err := CleanPath(name)
	if err != nil {
		return nil, err
	}
	if resumed, err := s.resumeInterrupted(ctx, tenant, clean, protocol); err != nil || resumed != nil {
		return resumed, err
	}
	return s.beginUpload(ctx, tenant, name, protocol, true)
}

func (s *Store) resumeInterrupted(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	release := func() {}
	if s.gate != nil {
		var err error
		release, err = s.gate.AcquireUpload(ctx, tenant)
		if err != nil {
			return nil, err
		}
	}
	var found model.Upload
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bUploads).Cursor()
		for _, v := c.First(); v != nil; _, v = c.Next() {
			var u model.Upload
			if json.Unmarshal(v, &u) != nil {
				continue
			}
			if u.Tenant == tenant && u.Path == name && u.State == model.StateInterrupted && u.UpdatedAt.After(found.UpdatedAt) {
				found = u
			}
		}
		if found.ID == "" {
			return nil
		}
		found.State = model.StateUploading
		found.Protocol = protocol
		found.Error = ""
		found.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bUploads), []byte(found.ID), found)
	})
	if err != nil || found.ID == "" {
		release()
		return nil, err
	}
	f, err := os.OpenFile(found.StagingPath, os.O_RDWR, 0o640)
	if err != nil {
		release()
		return nil, err
	}
	return &UploadHandle{store: s, upload: found, file: f, ctx: ctx, release: release}, nil
}

func (s *Store) beginUpload(ctx context.Context, tenant, name, protocol string, copyCurrent bool) (*UploadHandle, error) {
	if s.gate != nil && !s.gate.AllowNewUpload() {
		return nil, ErrUploadBlocked
	}
	clean, err := CleanPath(name)
	if err != nil || clean == "" {
		return nil, fmt.Errorf("invalid upload path: %w", err)
	}
	release := func() {}
	if s.gate != nil {
		release, err = s.gate.AcquireUpload(ctx, tenant)
		if err != nil {
			return nil, err
		}
	}
	id, err := randomID()
	if err != nil {
		release()
		return nil, err
	}
	dir := filepath.Join(s.root, "staging", tenant)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		release()
		return nil, err
	}
	stage := filepath.Join(dir, id+".partial")
	f, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o640)
	if err != nil {
		release()
		return nil, err
	}
	if copyCurrent {
		if current, _, openErr := s.OpenCurrent(tenant, clean); openErr == nil {
			if _, copyErr := io.Copy(f, current); copyErr != nil {
				current.Close()
				f.Close()
				os.Remove(stage)
				release()
				return nil, copyErr
			}
			_ = current.Close()
		}
	}
	now := s.now().UTC()
	u := model.Upload{ID: id, Tenant: tenant, Path: clean, Protocol: protocol, StagingPath: stage, State: model.StateUploading, CreatedAt: now, UpdatedAt: now}
	if err := s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(bUploads), []byte(id), u) }); err != nil {
		f.Close()
		os.Remove(stage)
		release()
		return nil, err
	}
	return &UploadHandle{store: s, upload: u, file: f, ctx: ctx, release: release}, nil
}

func (h *UploadHandle) ID() string   { return h.upload.ID }
func (h *UploadHandle) Path() string { return h.upload.Path }

func (h *UploadHandle) WriteAt(p []byte, off int64) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0, os.ErrClosed
	}
	if h.store.gate != nil {
		if err := h.store.gate.WaitN(h.ctx, h.upload.Tenant, len(p)); err != nil {
			h.failed = err
			return 0, err
		}
	}
	n, err := h.file.WriteAt(p, off)
	if err != nil {
		h.failed = err
	}
	return n, err
}

func (h *UploadHandle) ReadAt(p []byte, off int64) (int, error) { return h.file.ReadAt(p, off) }
func (h *UploadHandle) Truncate(size int64) error               { return h.file.Truncate(size) }

func (h *UploadHandle) TransferError(err error) { h.mu.Lock(); h.failed = err; h.mu.Unlock() }

func (h *UploadHandle) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	failed := h.failed
	h.mu.Unlock()
	if h.release != nil {
		defer h.release()
	}
	if failed != nil {
		_ = h.file.Close()
		return h.store.interrupt(h.upload, failed)
	}
	if err := h.file.Sync(); err != nil {
		_ = h.file.Close()
		return h.store.interrupt(h.upload, err)
	}
	if err := h.file.Close(); err != nil {
		return h.store.interrupt(h.upload, err)
	}
	return h.store.finalize(h.ctx, h.upload)
}

func (s *Store) interrupt(u model.Upload, cause error) error {
	u.State, u.UpdatedAt, u.Error = model.StateInterrupted, s.now().UTC(), cause.Error()
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(bUploads), []byte(u.ID), u) })
}

func hashFile(name string) (string, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, f, make([]byte, 1<<20))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func syncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) finalize(ctx context.Context, u model.Upload) error {
	now := s.now().UTC()
	u.State, u.UpdatedAt = model.StateFinalizing, now
	if err := s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(bUploads), []byte(u.ID), u) }); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return s.interrupt(u, ctx.Err())
	default:
	}
	digest, size, err := hashFile(u.StagingPath)
	if err != nil {
		return s.interrupt(u, err)
	}
	objDir := filepath.Join(s.root, "objects", u.Tenant)
	if err := os.MkdirAll(objDir, 0o750); err != nil {
		return s.interrupt(u, err)
	}
	blob := filepath.Join(objDir, u.ID+".blob")
	if err := os.Rename(u.StagingPath, blob); err != nil {
		return s.interrupt(u, err)
	}
	if err := syncDir(objDir); err != nil {
		return err
	}
	return s.publish(u, blob, digest, size)
}

func (s *Store) publish(u model.Upload, blob, digest string, size int64) error {
	now := s.now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		if _, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(u.ID)); err == nil {
			return tx.Bucket(bUploads).Delete([]byte(u.ID))
		}
		versions := tx.Bucket(bVersions)
		seq, err := versions.NextSequence()
		if err != nil {
			return err
		}
		qk := fmt.Sprintf("%s\x00%020d\x00%s", u.Tenant, now.UnixNano(), u.ID)
		o := model.ObjectVersion{ID: u.ID, Tenant: u.Tenant, Path: u.Path, BlobPath: blob, Size: size, SHA256: digest, ETag: digest, Version: seq, State: model.StateReady, QueueKey: qk, CreatedAt: now, UpdatedAt: now}
		if err := putJSON(tx.Bucket(bObjects), []byte(o.ID), o); err != nil {
			return err
		}
		if err := tx.Bucket(bNamespace).Put(nsKey(o.Tenant, o.Path), []byte(o.ID)); err != nil {
			return err
		}
		if err := tx.Bucket(bQueue).Put([]byte(qk), []byte(o.ID)); err != nil {
			return err
		}
		return tx.Bucket(bUploads).Delete([]byte(u.ID))
	})
}

func (s *Store) Object(id string) (model.ObjectVersion, error) {
	var o model.ObjectVersion
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		o, err = getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
		return err
	})
	return o, err
}

func (s *Store) UpdateObject(id string, update func(*model.ObjectVersion) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
		if err != nil {
			return err
		}
		if err := update(&o); err != nil {
			return err
		}
		o.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bObjects), []byte(id), o)
	})
}

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

func (s *Store) ClaimNext(tenant, clientID, prefix string, ttl time.Duration) (model.Claim, error) {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	cleanPrefix, err := CleanPath(prefix)
	if err != nil {
		return model.Claim{}, err
	}
	now := s.now().UTC()
	var claim model.Claim
	err = s.db.Update(func(tx *bolt.Tx) error {
		q := tx.Bucket(bQueue)
		c := q.Cursor()
		seek := []byte(tenant + "\x00")
		for k, id := c.Seek(seek); k != nil && strings.HasPrefix(string(k), tenant+"\x00"); k, id = c.Next() {
			o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
			if e != nil {
				continue
			}
			if cleanPrefix != "" && !strings.HasPrefix(o.Path, cleanPrefix) {
				continue
			}
			if o.State == model.StateLeased && o.LeaseUntil.After(now) {
				continue
			}
			if o.State != model.StateReady && o.State != model.StateLeased {
				continue
			}
			lease, e := randomID()
			if e != nil {
				return e
			}
			o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil, o.UpdatedAt = model.StateLeased, lease, clientID, now.Add(ttl), now
			claim = model.Claim{LeaseID: lease, ObjectID: o.ID, Tenant: tenant, ClientID: clientID, Path: o.Path, Size: o.Size, SHA256: o.SHA256, Version: o.Version, LeaseUntil: o.LeaseUntil}
			if err := putJSON(tx.Bucket(bObjects), []byte(o.ID), o); err != nil {
				return err
			}
			return putJSON(tx.Bucket(bClaims), []byte(lease), claim)
		}
		return ErrNotFound
	})
	return claim, err
}

func (s *Store) Renew(tenant, leaseID string, ttl time.Duration) (model.Claim, error) {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	var claim model.Claim
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		claim, err = getJSON[model.Claim](tx.Bucket(bClaims), []byte(leaseID))
		if err != nil {
			return err
		}
		if claim.Tenant != tenant {
			return ErrLeaseMismatch
		}
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(claim.ObjectID))
		if err != nil {
			return err
		}
		if o.LeaseID != leaseID || o.State != model.StateLeased {
			return ErrLeaseMismatch
		}
		now := s.now().UTC()
		claim.LeaseUntil = now.Add(ttl)
		o.LeaseUntil, o.UpdatedAt = claim.LeaseUntil, now
		if err := putJSON(tx.Bucket(bClaims), []byte(leaseID), claim); err != nil {
			return err
		}
		return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
	})
	return claim, err
}

func (s *Store) Release(tenant, leaseID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		claim, err := getJSON[model.Claim](tx.Bucket(bClaims), []byte(leaseID))
		if err != nil {
			return err
		}
		if claim.Tenant != tenant {
			return ErrLeaseMismatch
		}
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(claim.ObjectID))
		if err != nil {
			return err
		}
		if o.LeaseID == leaseID && o.State == model.StateLeased {
			o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil, o.UpdatedAt = model.StateReady, "", "", time.Time{}, s.now().UTC()
			if err := putJSON(tx.Bucket(bObjects), []byte(o.ID), o); err != nil {
				return err
			}
		}
		return tx.Bucket(bClaims).Delete([]byte(leaseID))
	})
}

func (s *Store) OpenClaim(tenant, objectID, leaseID string) (*os.File, model.ObjectVersion, error) {
	o, err := s.Object(objectID)
	if err != nil {
		return nil, o, err
	}
	if o.Tenant != tenant || o.State != model.StateLeased || o.LeaseID != leaseID || o.LeaseUntil.Before(s.now()) {
		return nil, o, ErrLeaseMismatch
	}
	f, err := os.Open(o.BlobPath)
	return f, o, err
}

func (s *Store) Commit(tenant, objectID, leaseID, digest string, size int64) (bool, error) {
	var o model.ObjectVersion
	alreadyDeleted := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if tombstone, err := getJSON[model.Tombstone](tx.Bucket(bTombstones), []byte(objectID)); err == nil {
			if tombstone.Tenant != tenant {
				return ErrNotFound
			}
			alreadyDeleted = true
			return nil
		}
		var err error
		o, err = getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(objectID))
		if err != nil {
			return err
		}
		if o.Tenant != tenant || o.LeaseID != leaseID || o.State != model.StateLeased {
			return ErrLeaseMismatch
		}
		if o.Size != size || !strings.EqualFold(o.SHA256, digest) {
			return ErrConflict
		}
		o.State, o.UpdatedAt = model.StateDeletePending, s.now().UTC()
		return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
	})
	if err != nil {
		return false, err
	}
	if alreadyDeleted {
		return false, nil
	}
	if err := s.finishDelete(o); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) finishDelete(o model.ObjectVersion) error {
	if err := os.Remove(o.BlobPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDir(filepath.Dir(o.BlobPath)); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		ns := tx.Bucket(bNamespace)
		if id := ns.Get(nsKey(o.Tenant, o.Path)); string(id) == o.ID {
			if err := ns.Delete(nsKey(o.Tenant, o.Path)); err != nil {
				return err
			}
		}
		if o.QueueKey != "" {
			_ = tx.Bucket(bQueue).Delete([]byte(o.QueueKey))
		}
		if o.LeaseID != "" {
			_ = tx.Bucket(bClaims).Delete([]byte(o.LeaseID))
		}
		t := model.Tombstone{ObjectID: o.ID, Tenant: o.Tenant, DeletedAt: s.now().UTC()}
		if err := putJSON(tx.Bucket(bTombstones), []byte(o.ID), t); err != nil {
			return err
		}
		return tx.Bucket(bObjects).Delete([]byte(o.ID))
	})
}

func (s *Store) Remove(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	var cleanup *model.ObjectVersion
	err = s.db.Update(func(tx *bolt.Tx) error {
		key := nsKey(tenant, clean)
		id := tx.Bucket(bNamespace).Get(key)
		if id == nil {
			return ErrNotFound
		}
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bNamespace).Delete(key); err != nil {
			return err
		}
		if o.State == model.StateReady {
			o.State = model.StateDeletePending
			cleanup = &o
			if err := putJSON(tx.Bucket(bObjects), []byte(o.ID), o); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && cleanup != nil {
		return s.finishDelete(*cleanup)
	}
	return err
}

func (s *Store) Rename(tenant, oldName, newName string) error {
	oldPath, err := CleanPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := CleanPath(newName)
	if err != nil || newPath == "" {
		return fmt.Errorf("invalid destination: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		ns := tx.Bucket(bNamespace)
		dirs := tx.Bucket(bDirectories)
		oldKey, newKey := nsKey(tenant, oldPath), nsKey(tenant, newPath)
		id := ns.Get(oldKey)
		if oldPath == newPath {
			if id != nil || dirs.Get(oldKey) != nil {
				return nil
			}
			prefix := nsKey(tenant, oldPath+"/")
			for _, bucket := range []*bolt.Bucket{ns, dirs} {
				k, _ := bucket.Cursor().Seek(prefix)
				if k != nil && strings.HasPrefix(string(k), string(prefix)) {
					return nil
				}
			}
			return ErrNotFound
		}
		if ns.Get(newKey) != nil || dirs.Get(newKey) != nil {
			return ErrConflict
		}
		destinationPrefix := nsKey(tenant, newPath+"/")
		for _, bucket := range []*bolt.Bucket{ns, dirs} {
			k, _ := bucket.Cursor().Seek(destinationPrefix)
			if k != nil && strings.HasPrefix(string(k), string(destinationPrefix)) {
				return ErrConflict
			}
		}
		if id == nil {
			if strings.HasPrefix(newPath, oldPath+"/") {
				return ErrConflict
			}
			type move struct {
				old, new []byte
				id       []byte
				dir      bool
			}
			moves := []move{}
			prefix := string(nsKey(tenant, oldPath+"/"))
			c := ns.Cursor()
			for k, v := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, v = c.Next() {
				suffix := strings.TrimPrefix(string(k), prefix)
				moves = append(moves, move{old: append([]byte(nil), k...), new: nsKey(tenant, newPath+"/"+suffix), id: append([]byte(nil), v...)})
			}
			dirPrefix := string(nsKey(tenant, oldPath))
			dc := dirs.Cursor()
			for k, _ := dc.Seek([]byte(dirPrefix)); k != nil && (string(k) == dirPrefix || strings.HasPrefix(string(k), dirPrefix+"/")); k, _ = dc.Next() {
				full := strings.TrimPrefix(string(k), tenant+"\x00")
				suffix := strings.TrimPrefix(full, oldPath)
				moves = append(moves, move{old: append([]byte(nil), k...), new: nsKey(tenant, newPath+suffix), dir: true})
			}
			if len(moves) == 0 {
				return ErrNotFound
			}
			for _, m := range moves {
				if m.dir {
					var e model.Entry
					e.Path = strings.TrimPrefix(string(m.new), tenant+"\x00")
					e.Directory = true
					e.UpdatedAt = s.now().UTC()
					if err := putJSON(dirs, m.new, e); err != nil {
						return err
					}
					if err := dirs.Delete(m.old); err != nil {
						return err
					}
					continue
				}
				o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), m.id)
				if err != nil {
					return err
				}
				o.Path = strings.TrimPrefix(string(m.new), tenant+"\x00")
				o.UpdatedAt = s.now().UTC()
				if err := putJSON(tx.Bucket(bObjects), m.id, o); err != nil {
					return err
				}
				if err := ns.Put(m.new, m.id); err != nil {
					return err
				}
				if err := ns.Delete(m.old); err != nil {
					return err
				}
			}
			return nil
		}
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
		if err != nil {
			return err
		}
		o.Path, o.UpdatedAt = newPath, s.now().UTC()
		if err := putJSON(tx.Bucket(bObjects), id, o); err != nil {
			return err
		}
		if err := ns.Put(newKey, id); err != nil {
			return err
		}
		return ns.Delete(oldKey)
	})
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
		if tx.Bucket(bDirectories).Get(nsKey(tenant, clean)) != nil {
			exists = true
			return nil
		}
		for _, b := range []*bolt.Bucket{tx.Bucket(bNamespace), tx.Bucket(bDirectories)} {
			prefix := nsKey(tenant, clean+"/")
			k, _ := b.Cursor().Seek(prefix)
			if k != nil && strings.HasPrefix(string(k), string(prefix)) {
				exists = true
				return nil
			}
		}
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
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range []*bolt.Bucket{tx.Bucket(bNamespace), tx.Bucket(bDirectories)} {
			prefix := nsKey(tenant, clean+"/")
			k, _ := b.Cursor().Seek(prefix)
			if k != nil && strings.HasPrefix(string(k), string(prefix)) {
				return ErrConflict
			}
		}
		key := nsKey(tenant, clean)
		if tx.Bucket(bDirectories).Get(key) == nil {
			return ErrNotFound
		}
		return tx.Bucket(bDirectories).Delete(key)
	})
}

func (s *Store) Mkdir(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	if clean == "" {
		return nil
	}
	e := model.Entry{Path: clean, Directory: true, UpdatedAt: s.now().UTC()}
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(bDirectories), nsKey(tenant, clean), e) })
}

type ListedEntry struct {
	Path      string
	Object    *model.ObjectVersion
	Directory bool
}

type Stats struct{ Objects, Ready, Leased, DeletePending, Uploads, Claims int }

func (s *Store) Stats() (Stats, error) {
	var out Stats
	err := s.db.View(func(tx *bolt.Tx) error {
		out.Uploads = tx.Bucket(bUploads).Stats().KeyN
		out.Claims = tx.Bucket(bClaims).Stats().KeyN
		c := tx.Bucket(bObjects).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				continue
			}
			out.Objects++
			switch o.State {
			case model.StateReady:
				out.Ready++
			case model.StateLeased:
				out.Leased++
			case model.StateDeletePending:
				out.DeletePending++
			}
		}
		return nil
	})
	return out, err
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
		c := ns.Cursor()
		seek := nsKey(tenant, prefix)
		for k, id := c.Seek(seek); k != nil && strings.HasPrefix(string(k), tenant+"\x00"+prefix); k, id = c.Next() {
			full := strings.TrimPrefix(string(k), tenant+"\x00")
			rest := strings.TrimPrefix(full, prefix)
			if rest == "" {
				continue
			}
			part := strings.SplitN(rest, "/", 2)
			if len(part) > 1 {
				entries[part[0]] = ListedEntry{Path: prefix + part[0], Directory: true}
				continue
			}
			o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
			if e != nil {
				continue
			}
			oo := o
			entries[part[0]] = ListedEntry{Path: full, Object: &oo}
		}
		dirs := tx.Bucket(bDirectories)
		dc := dirs.Cursor()
		for k, _ := dc.Seek(seek); k != nil && strings.HasPrefix(string(k), tenant+"\x00"+prefix); k, _ = dc.Next() {
			full := strings.TrimPrefix(string(k), tenant+"\x00")
			rest := strings.TrimPrefix(full, prefix)
			if rest == "" {
				continue
			}
			part := strings.SplitN(rest, "/", 2)[0]
			entries[part] = ListedEntry{Path: prefix + part, Directory: true}
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

func (s *Store) ListAll(tenant, prefix string) ([]model.ObjectVersion, error) {
	clean, err := CleanPath(prefix)
	if err != nil {
		return nil, err
	}
	out := []model.ObjectVersion{}
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bNamespace)
		c := b.Cursor()
		seek := nsKey(tenant, clean)
		for k, id := c.Seek(seek); k != nil && strings.HasPrefix(string(k), tenant+"\x00"+clean); k, id = c.Next() {
			o, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
			if e == nil {
				out = append(out, o)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

func (s *Store) Recover(ctx context.Context) error {
	var pending []model.ObjectVersion
	var finalizing []model.Upload
	now := s.now().UTC()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bObjects)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				continue
			}
			switch o.State {
			case model.StateLeased:
				if !o.LeaseUntil.After(now) {
					if o.LeaseID != "" {
						_ = tx.Bucket(bClaims).Delete([]byte(o.LeaseID))
					}
					o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil = model.StateReady, "", "", time.Time{}
					if err := putJSON(b, k, o); err != nil {
						return err
					}
				}
			case model.StateDeletePending:
				pending = append(pending, o)
			}
		}
		uploads := tx.Bucket(bUploads)
		uc := uploads.Cursor()
		for k, v := uc.First(); k != nil; k, v = uc.Next() {
			var u model.Upload
			if json.Unmarshal(v, &u) != nil {
				continue
			}
			if u.State == model.StateFinalizing {
				finalizing = append(finalizing, u)
			} else if u.State == model.StateUploading {
				u.State = model.StateInterrupted
				u.UpdatedAt = now
				u.Error = "server restarted during upload"
				if err := putJSON(uploads, k, u); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, o := range pending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := s.finishDelete(o); err != nil {
			return err
		}
	}
	for _, u := range finalizing {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		stage := u.StagingPath
		if _, err := os.Stat(stage); err == nil {
			if err = s.finalize(ctx, u); err != nil {
				return err
			}
			continue
		}
		blob := filepath.Join(s.root, "objects", u.Tenant, u.ID+".blob")
		digest, size, err := hashFile(blob)
		if err != nil {
			return fmt.Errorf("recover finalizing upload %s: %w", u.ID, err)
		}
		if err = s.publish(u, blob, digest, size); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Maintain(ctx context.Context, interval, partialTTL time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.maintenancePass(ctx, partialTTL)
		}
	}
}

func (s *Store) maintenancePass(ctx context.Context, partialTTL time.Duration) error {
	now := s.now().UTC()
	var pending []model.ObjectVersion
	var stale []model.Upload
	err := s.db.Update(func(tx *bolt.Tx) error {
		objects := tx.Bucket(bObjects)
		c := objects.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				continue
			}
			if o.State == model.StateLeased && !o.LeaseUntil.After(now) {
				if o.LeaseID != "" {
					_ = tx.Bucket(bClaims).Delete([]byte(o.LeaseID))
				}
				o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil = model.StateReady, "", "", time.Time{}
				o.UpdatedAt = now
				if err := putJSON(objects, k, o); err != nil {
					return err
				}
			} else if o.State == model.StateDeletePending {
				pending = append(pending, o)
			}
		}
		if partialTTL > 0 {
			uploads := tx.Bucket(bUploads)
			uc := uploads.Cursor()
			for _, v := uc.First(); v != nil; _, v = uc.Next() {
				var u model.Upload
				if json.Unmarshal(v, &u) == nil && u.State == model.StateInterrupted && now.Sub(u.UpdatedAt) >= partialTTL {
					stale = append(stale, u)
				}
			}
		}
		tombs := tx.Bucket(bTombstones)
		tc := tombs.Cursor()
		for k, v := tc.First(); k != nil; k, v = tc.Next() {
			var t model.Tombstone
			if json.Unmarshal(v, &t) == nil && now.Sub(t.DeletedAt) >= 7*24*time.Hour {
				if err := tombs.Delete(k); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, o := range pending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err = s.finishDelete(o); err != nil {
			continue
		}
	}
	for _, u := range stale {
		_ = os.Remove(u.StagingPath)
		_ = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bUploads).Delete([]byte(u.ID)) })
	}
	return nil
}
