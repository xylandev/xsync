package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

// OpenMode says how an upload relates to what is already stored at its path.
type OpenMode int

const (
	// ModeTruncate starts from an empty file (SFTP O_TRUNC, FTP STOR, S3 PUT).
	ModeTruncate OpenMode = iota
	// ModeResume keeps existing content (SFTP open without O_TRUNC, FTP REST).
	// Which content — an interrupted partial or the published version — is
	// decided by where the client starts writing, because that is the only
	// reliable signal of what the client believes is already there.
	ModeResume
	// ModeAppend appends to the content the uploader sees at the path (FTP
	// APPE, SFTP O_APPEND).
	ModeAppend
)

// base is content an upload inherits from an earlier interrupted upload or
// from the currently published version.
type base struct {
	interrupted *model.Upload
	current     *model.ObjectVersion
	size        int64
}

func (b base) source() string {
	if b.interrupted != nil {
		return b.interrupted.StagingPath
	}
	return b.current.BlobPath
}

// UploadHandle is one open upload. It accepts writes at arbitrary offsets and,
// on Close, publishes the file only if every byte from 0 to the end was either
// inherited from a base or written by the client.
type UploadHandle struct {
	store     *Store
	ctx       context.Context
	tenant    string
	path      string
	protocol  string
	mode      OpenMode
	unmetered bool

	mu         sync.Mutex
	upload     model.Upload
	file       *os.File
	resolved   bool
	candidates []base
	baseSize   int64
	// fillPrefix records that writes began past offset 0 without a matching
	// base; Close fills the prefix from a candidate or rejects the upload.
	fillPrefix bool
	appendMode int // 0 undecided, 1 relative offsets, 2 absolute offsets
	cov        coverage
	hasher     *streamHasher
	failed     error
	fatal      bool
	closed     bool
	release    func()
	reserved   func()
	meta       *ObjectMeta
}

// ObjectMeta is protocol metadata published together with the object.
type ObjectMeta struct {
	ETag     string
	Metadata map[string]string
	Tags     map[string]string
}

func (s *Store) BeginUpload(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	return s.OpenUpload(ctx, tenant, name, protocol, ModeTruncate)
}

// BeginUploadFromCurrent opens an upload that keeps existing content.
func (s *Store) BeginUploadFromCurrent(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	return s.OpenUpload(ctx, tenant, name, protocol, ModeResume)
}

// BeginInternalUpload starts an upload whose bytes are neither rate limited
// nor counted as ingress, for server-side assembly such as S3 multipart
// completion. The caller is responsible for reserving capacity.
func (s *Store) BeginInternalUpload(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	return s.openUpload(ctx, tenant, name, protocol, ModeTruncate, true)
}

func (s *Store) OpenUpload(ctx context.Context, tenant, name, protocol string, mode OpenMode) (*UploadHandle, error) {
	return s.openUpload(ctx, tenant, name, protocol, mode, false)
}

func (s *Store) openUpload(ctx context.Context, tenant, name, protocol string, mode OpenMode, internal bool) (*UploadHandle, error) {
	clean, err := CleanPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPath, err)
	}
	if clean == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if err := s.db.View(func(tx *bolt.Tx) error { return checkFilePath(tx, tenant, clean) }); err != nil {
		return nil, err
	}
	release := func() {}
	if !internal {
		if err := s.AdmitUpload(tenant); err != nil {
			return nil, err
		}
		if s.gate != nil {
			if release, err = s.gate.AcquireUpload(ctx, tenant); err != nil {
				return nil, err
			}
		}
	} else if s.draining.Load() {
		return nil, ErrDraining
	}
	h := &UploadHandle{store: s, ctx: ctx, tenant: tenant, path: clean, protocol: protocol, mode: mode, unmetered: internal, release: release}
	switch mode {
	case ModeTruncate:
		err = h.startFresh()
	case ModeResume:
		h.candidates, err = s.baseCandidates(tenant, clean)
	case ModeAppend:
		var cands []base
		if cands, err = s.baseCandidates(tenant, clean); err == nil {
			if len(cands) > 0 {
				err = h.adopt(cands[0])
			} else {
				err = h.startFresh()
			}
		}
	}
	if err != nil {
		h.releaseResources()
		return nil, err
	}
	s.inflight.Add(1)
	return h, nil
}

func (h *UploadHandle) releaseResources() {
	if h.release != nil {
		h.release()
		h.release = nil
	}
	if h.reserved != nil {
		h.reserved()
		h.reserved = nil
	}
}

// baseCandidates returns what an upload to name could continue from, the one
// the uploader currently sees first: the newest interrupted partial when it is
// newer than the published version, then the published version.
func (s *Store) baseCandidates(tenant, name string) ([]base, error) {
	var out []base
	err := s.db.View(func(tx *bolt.Tx) error {
		out = nil
		u, _ := newestInterrupted(tx, tenant, name)
		var cur *model.ObjectVersion
		if id := tx.Bucket(bNamespace).Get(nsKey(tenant, name)); id != nil {
			if o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id); err == nil {
				cur = &o
			}
		}
		var partial *base
		if u != nil {
			if info, err := os.Stat(u.StagingPath); err == nil {
				partial = &base{interrupted: u, size: info.Size()}
			}
		}
		if partial != nil && (cur == nil || u.UpdatedAt.After(cur.CreatedAt)) {
			out = append(out, *partial)
			partial = nil
		}
		if cur != nil {
			out = append(out, base{current: cur, size: cur.Size})
		}
		if partial != nil {
			out = append(out, *partial)
		}
		return nil
	})
	return out, err
}

func newestInterrupted(tx *bolt.Tx, tenant, name string) (*model.Upload, error) {
	prefix := []byte(tenant + "\x00" + name + "\x00")
	c := tx.Bucket(bUploadPaths).Cursor()
	var best *model.Upload
	for k, _ := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, _ = c.Next() {
		id := string(k[len(prefix):])
		u, err := getJSON[model.Upload](tx.Bucket(bUploads), []byte(id))
		if err != nil || u.State != model.StateInterrupted {
			continue
		}
		if best == nil || u.UpdatedAt.After(best.UpdatedAt) {
			uu := u
			best = &uu
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best, nil
}

func hasPrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

// startFresh creates an empty staging file and its upload record.
func (h *UploadHandle) startFresh() error {
	s := h.store
	id, err := randomID()
	if err != nil {
		return err
	}
	dir := filepath.Join(s.root, "staging", h.tenant)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	stage := filepath.Join(dir, id+".partial")
	f, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o640)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	u := model.Upload{ID: id, Tenant: h.tenant, Path: h.path, Protocol: h.protocol, StagingPath: stage, State: model.StateUploading, CreatedAt: now, UpdatedAt: now}
	if err := s.update(func(tx *bolt.Tx, d *delta) error {
		d.uploads++
		if err := tx.Bucket(bUploadPaths).Put(uploadPathKey(u.Tenant, u.Path, u.ID), nil); err != nil {
			return err
		}
		return putJSON(tx.Bucket(bUploads), []byte(id), u)
	}); err != nil {
		f.Close()
		os.Remove(stage)
		return err
	}
	h.upload, h.file, h.resolved = u, f, true
	h.hasher = newStreamHasher()
	return nil
}

// adopt makes b the content this upload continues from: an interrupted partial
// is resumed in place, a published version is cloned into a new staging file.
func (h *UploadHandle) adopt(b base) error {
	if b.interrupted != nil {
		return h.adoptInterrupted(*b.interrupted)
	}
	return h.cloneCurrent(*b.current)
}

func (h *UploadHandle) adoptInterrupted(u model.Upload) error {
	s := h.store
	claimed := false
	if err := s.update(func(tx *bolt.Tx, _ *delta) error {
		claimed = false
		cur, err := getJSON[model.Upload](tx.Bucket(bUploads), []byte(u.ID))
		if err != nil || cur.State != model.StateInterrupted {
			return nil
		}
		if err := tx.Bucket(bStale).Delete(timeIDKey(cur.UpdatedAt, cur.ID)); err != nil {
			return err
		}
		u = cur
		u.State, u.Protocol, u.Error, u.UpdatedAt = model.StateUploading, h.protocol, "", s.now().UTC()
		claimed = true
		return putJSON(tx.Bucket(bUploads), []byte(u.ID), u)
	}); err != nil {
		return err
	}
	if !claimed {
		// Someone else resumed or reclaimed it first.
		return fmt.Errorf("%w: interrupted upload is no longer available", ErrConflict)
	}
	f, err := os.OpenFile(u.StagingPath, os.O_RDWR, 0o640)
	if err != nil {
		_ = s.markUpload(u, model.StateFailed, err)
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		_ = s.markUpload(u, model.StateFailed, err)
		return err
	}
	h.upload, h.file, h.resolved = u, f, true
	h.baseSize = info.Size()
	h.cov.add(0, h.baseSize)
	// The inherited bytes were never hashed in this process.
	h.hasher = nil
	return nil
}

func (h *UploadHandle) cloneCurrent(o model.ObjectVersion) error {
	reserve, ok := h.store.Reserve(o.Size)
	if !ok {
		return ErrInsufficient
	}
	h.reserved = reserve
	if err := h.startFresh(); err != nil {
		return err
	}
	src, err := os.Open(o.BlobPath)
	if err != nil {
		return err
	}
	defer src.Close()
	// File-to-file io.Copy uses copy_file_range, which reflinks on XFS and
	// Btrfs and copies in the kernel elsewhere.
	n, err := io.Copy(h.file, src)
	if err != nil {
		return err
	}
	h.baseSize = n
	h.cov.add(0, n)
	h.hasher = nil
	return nil
}

func (h *UploadHandle) ID() string   { return h.upload.ID }
func (h *UploadHandle) Path() string { return h.path }

// BaseSize returns how many bytes the upload inherited.
func (h *UploadHandle) BaseSize() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.baseSize
}

// SetObjectMeta attaches protocol metadata that is published atomically with
// the object.
func (h *UploadHandle) SetObjectMeta(m ObjectMeta) {
	h.mu.Lock()
	h.meta = &m
	h.mu.Unlock()
}

// resolve picks the base for a resumed upload from the first write offset.
func (h *UploadHandle) resolve(off int64) error {
	if off == 0 {
		return h.startFresh()
	}
	for _, c := range h.candidates {
		if c.size == off {
			return h.adopt(c)
		}
	}
	for _, c := range h.candidates {
		if c.size > off {
			return h.adopt(c)
		}
	}
	// Writes may arrive out of order (SFTP pipelines them), so the lowest
	// offset is not necessarily first. Write sparsely and settle at Close.
	if err := h.startFresh(); err != nil {
		return err
	}
	h.fillPrefix = true
	return nil
}

func (h *UploadHandle) WriteAt(p []byte, off int64) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.writeLocked(p, off, h.mode == ModeAppend)
}

func (h *UploadHandle) writeLocked(p []byte, off int64, translate bool) (int, error) {
	if h.closed {
		return 0, os.ErrClosed
	}
	if h.failed != nil {
		return 0, h.failed
	}
	if off < 0 {
		return 0, ErrInvalidOffset
	}
	if !h.resolved {
		if err := h.resolve(off); err != nil {
			h.failed, h.fatal = err, true
			return 0, err
		}
	}
	if translate {
		off = h.appendOffset(off)
	}
	if h.store.gate != nil {
		var err error
		if h.unmetered {
			err = h.store.gate.CheckCritical()
		} else {
			err = h.store.gate.WaitN(h.ctx, h.tenant, len(p))
		}
		if err != nil {
			h.failed = err
			return 0, err
		}
	}
	n, err := h.file.WriteAt(p, off)
	if n > 0 {
		h.cov.add(off, off+int64(n))
		if h.hasher != nil {
			h.hasher.write(p[:n], off)
		}
	}
	if err != nil {
		h.failed = err
	}
	return n, err
}

// appendOffset maps a client offset to a file offset in append mode. FTP APPE
// and most SFTP clients count append offsets from zero; some SFTP clients send
// absolute offsets starting at the current size. The first write decides.
func (h *UploadHandle) appendOffset(off int64) int64 {
	if h.appendMode == 0 {
		h.appendMode = 2
		if h.baseSize > 0 && off < h.baseSize {
			h.appendMode = 1
		}
	}
	if h.appendMode == 1 {
		return off + h.baseSize
	}
	return off
}

// Append writes p at the end of the data written so far. FTP uses it for
// APPE, where the client sends no offsets at all.
func (h *UploadHandle) Append(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	off := int64(0)
	if h.resolved {
		off = h.cov.end()
	}
	return h.writeLocked(p, off, false)
}

func (h *UploadHandle) ReadAt(p []byte, off int64) (int, error) {
	h.mu.Lock()
	f := h.file
	h.mu.Unlock()
	if f == nil {
		return 0, io.EOF
	}
	return f.ReadAt(p, off)
}

// Truncate sets the file size, as SFTP SETSTAT/FSETSTAT with a size does.
func (h *UploadHandle) Truncate(size int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return os.ErrClosed
	}
	if size < 0 {
		return ErrInvalidOffset
	}
	if !h.resolved {
		var err error
		if size == 0 {
			err = h.startFresh()
		} else {
			err = ErrInvalidOffset
			for _, c := range h.candidates {
				if c.size >= size {
					err = h.adopt(c)
					break
				}
			}
		}
		if err != nil {
			h.failed, h.fatal = err, true
			return err
		}
	}
	old := h.cov.end()
	if err := h.file.Truncate(size); err != nil {
		h.failed = err
		return err
	}
	h.cov.clip(size)
	if size > old {
		// Extending with ftruncate defines the new bytes as zeros.
		h.cov.add(old, size)
	}
	if h.baseSize > size {
		h.baseSize = size
	}
	if h.hasher != nil {
		h.hasher.truncate(size)
	}
	return nil
}

// TransferError records that the client connection failed. The upload is kept
// as an interrupted partial that a later upload can resume.
func (h *UploadHandle) TransferError(err error) {
	h.mu.Lock()
	if h.failed == nil {
		h.failed = err
	}
	h.mu.Unlock()
}

// Fail records that the uploaded content is invalid (for example a checksum
// mismatch). The upload is discarded rather than kept for resumption.
func (h *UploadHandle) Fail(err error) {
	h.mu.Lock()
	h.failed, h.fatal = err, true
	h.mu.Unlock()
}

// Close publishes the upload, or records why it could not be published. It
// returns nil only when the object is durably in the catalog, because every
// protocol turns this result into the acknowledgement the uploader sees.
func (h *UploadHandle) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()
	s := h.store
	defer s.inflight.Add(-1)
	defer h.releaseResources()

	if h.failed != nil {
		if h.file == nil {
			return fmt.Errorf("upload not published: %w", h.failed)
		}
		if h.fatal {
			return s.discard(h.upload, h.file, h.failed)
		}
		return s.interruptHandle(h, h.failed)
	}
	if !h.resolved {
		if len(h.candidates) > 0 {
			// Opened without truncating and closed without writing: the
			// existing content is unchanged, nothing to publish.
			return nil
		}
		if err := h.startFresh(); err != nil {
			return fmt.Errorf("upload not published: %w", err)
		}
	}
	if err := h.settle(); err != nil {
		if errors.Is(err, ErrIncomplete) {
			return s.interruptHandle(h, err)
		}
		return s.discard(h.upload, h.file, err)
	}
	info, err := h.file.Stat()
	if err == nil {
		err = h.file.Sync()
	}
	if err != nil {
		return s.discard(h.upload, h.file, err)
	}
	var pre *precomputed
	if h.hasher != nil && h.baseSize == 0 {
		pre = h.hasher.result(info.Size())
	}
	if err := h.file.Close(); err != nil {
		return s.fail(h.upload, err)
	}
	h.file = nil
	return s.finalize(h.upload, pre, h.meta)
}

// settle fills a deferred prefix and verifies that the file has no gaps.
func (h *UploadHandle) settle() error {
	if h.fillPrefix {
		first := h.cov.start()
		if first > 0 {
			var chosen *base
			for i, c := range h.candidates {
				if c.size == first {
					chosen = &h.candidates[i]
					break
				}
			}
			if chosen == nil {
				for i, c := range h.candidates {
					if c.size > first {
						chosen = &h.candidates[i]
						break
					}
				}
			}
			if chosen == nil {
				return fmt.Errorf("%w: writes start at offset %d but nothing of that size exists to continue", ErrInvalidOffset, first)
			}
			if err := h.copyPrefix(*chosen, first); err != nil {
				return err
			}
			h.hasher = nil
		}
	}
	info, err := h.file.Stat()
	if err != nil {
		return err
	}
	if !h.cov.covers(info.Size()) {
		return fmt.Errorf("%w: %d bytes on disk, contiguous data ends at %d", ErrIncomplete, info.Size(), h.cov.contiguous())
	}
	return nil
}

func (h *UploadHandle) copyPrefix(b base, n int64) error {
	src, err := os.Open(b.source())
	if err != nil {
		return err
	}
	defer src.Close()
	if _, err := io.Copy(io.NewOffsetWriter(h.file, 0), io.NewSectionReader(src, 0, n)); err != nil {
		return err
	}
	h.cov.add(0, n)
	return nil
}

func (s *Store) markUpload(u model.Upload, state model.State, cause error) error {
	prev := u.UpdatedAt
	u.State, u.UpdatedAt = state, s.now().UTC()
	if cause != nil {
		u.Error = cause.Error()
	}
	return s.update(func(tx *bolt.Tx, _ *delta) error {
		cur, err := getJSON[model.Upload](tx.Bucket(bUploads), []byte(u.ID))
		if err == nil {
			prev = cur.UpdatedAt
		}
		_ = tx.Bucket(bStale).Delete(timeIDKey(prev, u.ID))
		if state == model.StateInterrupted || state == model.StateFailed {
			if err := tx.Bucket(bStale).Put(timeIDKey(u.UpdatedAt, u.ID), nil); err != nil {
				return err
			}
		}
		return putJSON(tx.Bucket(bUploads), []byte(u.ID), u)
	})
}

// interruptHandle parks an upload that failed before the client finished, so
// it can be resumed. The staging file is cut back to its longest gap-free
// prefix, which is exactly the size a resuming client will be shown.
func (s *Store) interruptHandle(h *UploadHandle, cause error) error {
	if valid := h.cov.contiguous(); valid >= 0 {
		_ = h.file.Truncate(valid)
	}
	_ = h.file.Sync()
	_ = h.file.Close()
	h.file = nil
	if err := s.markUpload(h.upload, model.StateInterrupted, cause); err != nil {
		return errors.Join(fmt.Errorf("upload interrupted: %w", cause), err)
	}
	return fmt.Errorf("upload interrupted and kept for resumption: %w", cause)
}

// discard drops an upload whose content must not be published or resumed.
func (s *Store) discard(u model.Upload, f *os.File, cause error) error {
	if f != nil {
		_ = f.Close()
	}
	return s.fail(u, cause)
}

// fail marks an upload FAILED and removes its data. It always returns an
// error describing why the upload was not published.
func (s *Store) fail(u model.Upload, cause error) error {
	_ = os.Remove(u.StagingPath)
	_ = os.Remove(s.blobPath(u.Tenant, u.ID))
	notPublished := fmt.Errorf("upload not published: %w", cause)
	if err := s.markUpload(u, model.StateFailed, cause); err != nil {
		return errors.Join(notPublished, err)
	}
	return notPublished
}

func (s *Store) blobPath(tenant, id string) string {
	return filepath.Join(s.root, "objects", tenant, id+".blob")
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

// precomputed carries a digest that was produced while the upload streamed.
type precomputed struct {
	digest string
	size   int64
}

// finalize moves a complete staging file into place and publishes it. Every
// failure is returned, and the upload is marked FAILED, so the uploader is
// never told a transfer succeeded when the object is not in the catalog.
func (s *Store) finalize(u model.Upload, pre *precomputed, meta *ObjectMeta) error {
	u.State, u.UpdatedAt = model.StateFinalizing, s.now().UTC()
	if err := s.update(func(tx *bolt.Tx, _ *delta) error { return putJSON(tx.Bucket(bUploads), []byte(u.ID), u) }); err != nil {
		return s.fail(u, err)
	}
	digest, size := "", int64(0)
	if pre != nil {
		digest, size = pre.digest, pre.size
	} else {
		var err error
		if digest, size, err = hashFile(u.StagingPath); err != nil {
			return s.fail(u, err)
		}
	}
	objDir := filepath.Join(s.root, "objects", u.Tenant)
	created := false
	if _, err := os.Stat(objDir); errors.Is(err, os.ErrNotExist) {
		created = true
	}
	if err := os.MkdirAll(objDir, 0o750); err != nil {
		return s.fail(u, err)
	}
	if created {
		if err := syncDir(filepath.Join(s.root, "objects")); err != nil {
			return s.fail(u, err)
		}
	}
	blob := s.blobPath(u.Tenant, u.ID)
	if err := os.Rename(u.StagingPath, blob); err != nil {
		return s.fail(u, err)
	}
	if err := syncDir(objDir); err != nil {
		return s.fail(u, err)
	}
	if err := s.publish(u, blob, digest, size, meta); err != nil {
		return s.fail(u, err)
	}
	return nil
}

// Held reports whether a path matches one of the hold patterns.
func Held(patterns []string, p string) bool {
	name := path.Base(p)
	for _, pat := range patterns {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
	}
	return false
}

func (s *Store) publish(u model.Upload, blob, digest string, size int64, meta *ObjectMeta) error {
	now := s.now().UTC()
	pol := s.policyFor(u.Tenant)
	var victim *model.ObjectVersion
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		victim = nil
		uploads := tx.Bucket(bUploads)
		dropUpload := func() error {
			_ = tx.Bucket(bUploadPaths).Delete(uploadPathKey(u.Tenant, u.Path, u.ID))
			if uploads.Get([]byte(u.ID)) == nil {
				return nil
			}
			d.uploads--
			return uploads.Delete([]byte(u.ID))
		}
		if _, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(u.ID)); err == nil {
			return dropUpload()
		}
		if err := checkFilePath(tx, u.Tenant, u.Path); err != nil {
			return err
		}
		seq, err := tx.Bucket(bVersions).NextSequence()
		if err != nil {
			return err
		}
		o := model.ObjectVersion{ID: u.ID, Tenant: u.Tenant, Path: u.Path, BlobPath: blob, Size: size, SHA256: digest, ETag: digest, Version: seq, CreatedAt: now, UpdatedAt: now}
		if meta != nil {
			if meta.ETag != "" {
				o.ETag = meta.ETag
			}
			o.Metadata, o.Tags = meta.Metadata, meta.Tags
		}
		var err2 error
		if victim, err2 = s.replacePath(tx, d, u.Tenant, u.Path, pol.Supersede, "superseded"); err2 != nil {
			return err2
		}
		if err := s.place(tx, d, &o, "", pol, now); err != nil {
			return err
		}
		if err := tx.Bucket(bNamespace).Put(nsKey(o.Tenant, o.Path), []byte(o.ID)); err != nil {
			return err
		}
		return dropUpload()
	})
	if err == nil && victim != nil {
		s.collect(victim.ID, victim.Tenant, victim.BlobPath, victim.Size)
	}
	return err
}

// place stores o in the state its name calls for: HELD for temporary names,
// otherwise READY at the tail of the queue. from is o's previous state.
func (s *Store) place(tx *bolt.Tx, d *delta, o *model.ObjectVersion, from model.State, pol Policy, now time.Time) error {
	if Held(pol.HoldPatterns, o.Path) {
		o.State = model.StateHeld
		if err := tx.Bucket(bHeld).Put(timeIDKey(o.CreatedAt, o.ID), nil); err != nil {
			return err
		}
	} else {
		o.State = model.StateReady
		if err := enqueue(tx, o, now.Add(pol.PublishDelay)); err != nil {
			return err
		}
	}
	d.move(*o, from, o.State)
	return putJSON(tx.Bucket(bObjects), []byte(o.ID), *o)
}

// replacePath detaches whatever object is published at p before something
// else takes the path. With supersede, an undelivered object is deleted and a
// leased one is retracted; otherwise it keeps its place in the queue.
// It returns the deleted object, whose blob the caller unlinks after commit.
func (s *Store) replacePath(tx *bolt.Tx, d *delta, tenant, p string, supersede bool, reason string) (*model.ObjectVersion, error) {
	ns := tx.Bucket(bNamespace)
	id := bytes.Clone(ns.Get(nsKey(tenant, p)))
	if id == nil {
		return nil, nil
	}
	if err := ns.Delete(nsKey(tenant, p)); err != nil {
		return nil, err
	}
	if !supersede {
		return nil, nil
	}
	prev, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), id)
	if err != nil {
		return nil, nil
	}
	if prev.State == model.StateLeased {
		prev.Retracted = true
		return nil, putJSON(tx.Bucket(bObjects), id, prev)
	}
	return &prev, s.deleteObjectTx(tx, d, prev, reason)
}

// checkFilePath rejects a file path that is a directory or lies under a file.
func checkFilePath(tx *bolt.Tx, tenant, p string) error {
	if tx.Bucket(bDirectories).Get(nsKey(tenant, p)) != nil || hasChildren(tx, tenant, p) {
		return ErrIsDirectory
	}
	return checkAncestors(tx, tenant, p)
}

func checkAncestors(tx *bolt.Tx, tenant, p string) error {
	ns := tx.Bucket(bNamespace)
	for dir := path.Dir(p); dir != "." && dir != "/" && dir != ""; dir = path.Dir(dir) {
		if ns.Get(nsKey(tenant, dir)) != nil {
			return ErrNotDirectory
		}
	}
	return nil
}

// coverage tracks which byte ranges of a staging file hold intended data.
type coverage struct{ spans [][2]int64 }

func (c *coverage) add(start, end int64) {
	if end <= start {
		return
	}
	spans := append(c.spans, [2]int64{start, end})
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	merged := spans[:0]
	for _, s := range spans {
		if n := len(merged); n > 0 && s[0] <= merged[n-1][1] {
			if s[1] > merged[n-1][1] {
				merged[n-1][1] = s[1]
			}
			continue
		}
		merged = append(merged, s)
	}
	c.spans = merged
}

func (c *coverage) clip(size int64) {
	out := c.spans[:0]
	for _, s := range c.spans {
		if s[0] >= size {
			continue
		}
		if s[1] > size {
			s[1] = size
		}
		out = append(out, s)
	}
	c.spans = out
}

func (c *coverage) start() int64 {
	if len(c.spans) == 0 {
		return 0
	}
	return c.spans[0][0]
}

func (c *coverage) end() int64 {
	if len(c.spans) == 0 {
		return 0
	}
	return c.spans[len(c.spans)-1][1]
}

// contiguous returns the length of the gap-free prefix starting at 0.
func (c *coverage) contiguous() int64 {
	if len(c.spans) == 0 || c.spans[0][0] != 0 {
		return 0
	}
	return c.spans[0][1]
}

// covers reports whether [0,size) is fully written.
func (c *coverage) covers(size int64) bool {
	if size == 0 {
		return true
	}
	return c.contiguous() >= size
}

// streamHasher computes SHA-256 while data streams in. SFTP clients pipeline
// writes, so packets can arrive slightly out of order; a bounded reorder
// buffer absorbs that instead of forcing a full reread at Close.
type streamHasher struct {
	h       hash.Hash
	next    int64
	pending map[int64][]byte
	held    int
	valid   bool
}

const maxReorderBytes = 32 << 20

func newStreamHasher() *streamHasher {
	return &streamHasher{h: sha256.New(), pending: map[int64][]byte{}, valid: true}
}

func (s *streamHasher) write(p []byte, off int64) {
	if !s.valid {
		return
	}
	switch {
	case off == s.next:
		s.h.Write(p)
		s.next += int64(len(p))
		for {
			q, ok := s.pending[s.next]
			if !ok {
				break
			}
			delete(s.pending, s.next)
			s.held -= len(q)
			s.h.Write(q)
			s.next += int64(len(q))
		}
	case off > s.next && s.held+len(p) <= maxReorderBytes:
		if _, dup := s.pending[off]; dup {
			s.invalidate()
			return
		}
		s.pending[off] = append([]byte(nil), p...)
		s.held += len(p)
	default:
		// A rewrite of hashed bytes, or too much reordering.
		s.invalidate()
	}
}

func (s *streamHasher) invalidate() {
	s.valid, s.pending, s.held = false, nil, 0
}

func (s *streamHasher) truncate(size int64) {
	if !s.valid || size != s.next || len(s.pending) > 0 {
		s.invalidate()
	}
}

// result returns the digest if it covers exactly size bytes.
func (s *streamHasher) result(size int64) *precomputed {
	if !s.valid || len(s.pending) > 0 || s.next != size {
		return nil
	}
	return &precomputed{digest: hex.EncodeToString(s.h.Sum(nil)), size: size}
}
