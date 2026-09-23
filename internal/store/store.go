package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	AllowBytes(n int64) bool
	WaitN(context.Context, string, int) error
	AcquireUpload(context.Context, string) (func(), error)
}

type Store struct {
	root     string
	db       *bolt.DB
	gate     UploadGate
	log      *slog.Logger
	now      func() time.Time
	count    counters
	inflight atomic.Int64
}

type Stats struct{ Objects, Ready, Leased, DeletePending, Uploads, Claims int }

// counters mirrors the catalog's state distribution in memory so that a metrics
// scrape does not have to walk every record. Recover rebuilds it at startup from
// the one full scan it already performs.
type counters struct {
	mu sync.Mutex
	s  Stats
}

func (c *counters) set(s Stats) {
	c.mu.Lock()
	c.s = s
	c.mu.Unlock()
}

func (c *counters) snapshot() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s
}

func (c *counters) apply(d delta) {
	c.mu.Lock()
	c.s.Objects += d.objects
	c.s.Ready += d.ready
	c.s.Leased += d.leased
	c.s.DeletePending += d.deletePending
	c.s.Uploads += d.uploads
	c.s.Claims += d.claims
	c.mu.Unlock()
}

// delta accumulates counter changes made inside a write transaction. It is only
// applied once the transaction commits, so a rollback cannot skew the counters.
type delta struct {
	objects, ready, leased, deletePending, uploads, claims int
}

// stateChange records an object moving between states. An empty state means the
// object is being created (as "to") or removed (as "from").
func (d *delta) stateChange(from, to model.State) {
	if from == to {
		return
	}
	switch from {
	case model.StateReady:
		d.ready--
	case model.StateLeased:
		d.leased--
	case model.StateDeletePending:
		d.deletePending--
	}
	switch to {
	case model.StateReady:
		d.ready++
	case model.StateLeased:
		d.leased++
	case model.StateDeletePending:
		d.deletePending++
	}
}

// mutate runs fn in a batched write transaction and applies its counter delta
// only after the transaction commits.
//
// bbolt coalesces concurrent Batch calls into a single commit, which is what
// keeps concurrent uploads from serializing on one fsync per metadata write.
// The trade-off is that a lone caller waits out the batch window, so this is
// for throughput-bound paths where many clients write at once: use mutateNow
// where a single caller is blocked on the result.
//
// A batched closure may be replayed, so fn must be safe to retry; the delta is
// reset on every attempt for that reason.
func (s *Store) mutate(fn func(tx *bolt.Tx, d *delta) error) error {
	return s.apply(s.db.Batch, fn)
}

// mutateNow commits immediately, for latency-bound operations where batching
// would only add the batch window to a waiting client's round trip.
func (s *Store) mutateNow(fn func(tx *bolt.Tx, d *delta) error) error {
	return s.apply(s.db.Update, fn)
}

// mutateUpload commits metadata for an upload in flight. With several uploads
// running, batching coalesces their commits into one fsync. With a single
// upload there is nothing to coalesce with, and batching would only make that
// one client wait out the batch window, so it commits immediately.
//
// The in-flight count is a performance heuristic: if it drifts, throughput
// changes but correctness does not.
func (s *Store) mutateUpload(fn func(tx *bolt.Tx, d *delta) error) error {
	if s.inflight.Load() > 1 {
		return s.mutate(fn)
	}
	return s.mutateNow(fn)
}

func (s *Store) apply(run func(func(*bolt.Tx) error) error, fn func(tx *bolt.Tx, d *delta) error) error {
	var d delta
	if err := run(func(tx *bolt.Tx) error {
		d = delta{}
		return fn(tx, &d)
	}); err != nil {
		return err
	}
	s.count.apply(d)
	return nil
}

func Open(root string, gate UploadGate, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	for _, dir := range []string{"staging", "objects", "metadata"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(filepath.Join(root, "metadata", "catalog.db"), 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, db: db, gate: gate, log: log, now: time.Now}
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

	// Sequential writes are hashed as they stream so finalize does not have to
	// read the whole staging file a second time. An out-of-order write or a
	// truncate invalidates the running digest and finalize rehashes instead.
	seqHash   hash.Hash
	seqOffset int64
	seqValid  bool

	// unmetered skips the capacity limiter for bytes that are not client
	// ingress, such as server-side multipart assembly.
	unmetered bool
}

// precomputed carries a digest that was produced while the upload streamed.
type precomputed struct {
	digest string
	size   int64
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
	// seqValid stays false: the bytes already in the staging file were never
	// hashed, so finalize must reread the file.
	s.inflight.Add(1)
	return &UploadHandle{store: s, upload: found, file: f, ctx: ctx, release: release}, nil
}

func (s *Store) beginUpload(ctx context.Context, tenant, name, protocol string, copyCurrent bool) (*UploadHandle, error) {
	if s.gate != nil && !s.gate.AllowNewUpload() {
		return nil, ErrUploadBlocked
	}
	clean, err := CleanPath(name)
	if err != nil {
		return nil, fmt.Errorf("invalid upload path: %w", err)
	}
	if clean == "" {
		return nil, errors.New("invalid upload path: empty path")
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
	seqHash := sha256.New()
	var seqOffset int64
	if copyCurrent {
		if current, _, openErr := s.OpenCurrent(tenant, clean); openErr == nil {
			copied, copyErr := io.Copy(io.MultiWriter(f, seqHash), current)
			if copyErr != nil {
				current.Close()
				f.Close()
				os.Remove(stage)
				release()
				return nil, copyErr
			}
			_ = current.Close()
			seqOffset = copied
		}
	}
	now := s.now().UTC()
	u := model.Upload{ID: id, Tenant: tenant, Path: clean, Protocol: protocol, StagingPath: stage, State: model.StateUploading, CreatedAt: now, UpdatedAt: now}
	if err := s.mutateUpload(func(tx *bolt.Tx, d *delta) error {
		d.uploads++
		return putJSON(tx.Bucket(bUploads), []byte(id), u)
	}); err != nil {
		f.Close()
		os.Remove(stage)
		release()
		return nil, err
	}
	s.inflight.Add(1)
	return &UploadHandle{store: s, upload: u, file: f, ctx: ctx, release: release, seqHash: seqHash, seqOffset: seqOffset, seqValid: true}, nil
}

// BeginInternalUpload starts an upload whose bytes are neither rate limited nor
// counted as ingress. It exists for server-side assembly such as S3 multipart
// completion, where the bytes were already metered when the parts arrived.
func (s *Store) BeginInternalUpload(ctx context.Context, tenant, name, protocol string) (*UploadHandle, error) {
	h, err := s.beginUpload(ctx, tenant, name, protocol, false)
	if err != nil {
		return nil, err
	}
	h.unmetered = true
	return h, nil
}

// HasRoomFor reports whether n additional bytes fit under the capacity
// watermarks. Callers that briefly need a second copy of an object on disk
// should budget for it before they start writing.
func (s *Store) HasRoomFor(n int64) bool {
	if s.gate == nil {
		return true
	}
	return s.gate.AllowBytes(n)
}

func (h *UploadHandle) ID() string   { return h.upload.ID }
func (h *UploadHandle) Path() string { return h.upload.Path }

func (h *UploadHandle) WriteAt(p []byte, off int64) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0, os.ErrClosed
	}
	if h.store.gate != nil && !h.unmetered {
		if err := h.store.gate.WaitN(h.ctx, h.upload.Tenant, len(p)); err != nil {
			h.failed = err
			return 0, err
		}
	}
	n, err := h.file.WriteAt(p, off)
	if n > 0 {
		if h.seqValid && off == h.seqOffset {
			_, _ = h.seqHash.Write(p[:n])
			h.seqOffset += int64(n)
		} else {
			h.seqValid = false
		}
	}
	if err != nil {
		h.failed = err
	}
	return n, err
}

func (h *UploadHandle) ReadAt(p []byte, off int64) (int, error) { return h.file.ReadAt(p, off) }
func (h *UploadHandle) Truncate(size int64) error {
	h.mu.Lock()
	h.seqValid = false
	h.mu.Unlock()
	return h.file.Truncate(size)
}

// streamDigest returns the digest accumulated during writing, but only when the
// staging file contains exactly the bytes that were hashed. Any gap means the
// running digest is not trustworthy and finalize must reread the file.
func (h *UploadHandle) streamDigest() *precomputed {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.seqValid {
		return nil
	}
	info, err := h.file.Stat()
	if err != nil || info.Size() != h.seqOffset {
		return nil
	}
	return &precomputed{digest: hex.EncodeToString(h.seqHash.Sum(nil)), size: h.seqOffset}
}

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
	defer h.store.inflight.Add(-1)
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
	pre := h.streamDigest()
	if err := h.file.Close(); err != nil {
		return h.store.interrupt(h.upload, err)
	}
	return h.store.finalize(h.ctx, h.upload, pre)
}

func (s *Store) markUpload(u model.Upload, state model.State, cause error) error {
	u.State, u.UpdatedAt, u.Error = state, s.now().UTC(), cause.Error()
	return s.mutateUpload(func(tx *bolt.Tx, _ *delta) error { return putJSON(tx.Bucket(bUploads), []byte(u.ID), u) })
}

// interrupt parks an upload that can still be resumed by path.
func (s *Store) interrupt(u model.Upload, cause error) error {
	return s.markUpload(u, model.StateInterrupted, cause)
}

// fail parks an upload that cannot be recovered. Unlike an interrupted upload it
// is never resumed; maintenance reclaims it once partial_ttl expires.
func (s *Store) fail(u model.Upload, cause error) error {
	return s.markUpload(u, model.StateFailed, cause)
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

func (s *Store) finalize(ctx context.Context, u model.Upload, pre *precomputed) error {
	now := s.now().UTC()
	u.State, u.UpdatedAt = model.StateFinalizing, now
	if err := s.mutateUpload(func(tx *bolt.Tx, _ *delta) error { return putJSON(tx.Bucket(bUploads), []byte(u.ID), u) }); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return s.interrupt(u, ctx.Err())
	default:
	}
	digest, size := "", int64(0)
	if pre != nil {
		digest, size = pre.digest, pre.size
	} else {
		var err error
		if digest, size, err = hashFile(u.StagingPath); err != nil {
			return s.interrupt(u, err)
		}
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
	return s.mutateUpload(func(tx *bolt.Tx, d *delta) error {
		uploads := tx.Bucket(bUploads)
		dropUpload := func() error {
			if uploads.Get([]byte(u.ID)) == nil {
				return nil
			}
			d.uploads--
			return uploads.Delete([]byte(u.ID))
		}
		if _, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(u.ID)); err == nil {
			return dropUpload()
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
		d.objects++
		d.stateChange("", model.StateReady)
		return dropUpload()
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
	return s.mutateUpload(func(tx *bolt.Tx, d *delta) error {
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
		if err != nil {
			return err
		}
		before := o.State
		if err := update(&o); err != nil {
			return err
		}
		o.UpdatedAt = s.now().UTC()
		d.stateChange(before, o.State)
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
	var claimed bool
	// Only claimable objects live in the queue, so this walks past at most the
	// entries filtered out by prefix rather than every outstanding lease.
	err = s.mutateNow(func(tx *bolt.Tx, d *delta) error {
		claimed = false
		objects, q := tx.Bucket(bObjects), tx.Bucket(bQueue)
		var (
			orphans  [][]byte
			foundKey []byte
			found    model.ObjectVersion
		)
		c := q.Cursor()
		seek := []byte(tenant + "\x00")
		for k, id := c.Seek(seek); k != nil && bytes.HasPrefix(k, seek); k, id = c.Next() {
			o, e := getJSON[model.ObjectVersion](objects, id)
			if e != nil {
				orphans = append(orphans, bytes.Clone(k))
				continue
			}
			if o.State != model.StateReady {
				continue
			}
			if cleanPrefix != "" && !pathHasPrefix(o.Path, cleanPrefix) {
				continue
			}
			foundKey, found = bytes.Clone(k), o
			break
		}
		for _, k := range orphans {
			if err := q.Delete(k); err != nil {
				return err
			}
		}
		if foundKey == nil {
			return nil
		}
		lease, err := randomID()
		if err != nil {
			return err
		}
		found.State, found.LeaseID, found.LeaseClient, found.LeaseUntil, found.UpdatedAt = model.StateLeased, lease, clientID, now.Add(ttl), now
		claim = model.Claim{LeaseID: lease, ObjectID: found.ID, Tenant: tenant, ClientID: clientID, Path: found.Path, Size: found.Size, SHA256: found.SHA256, Version: found.Version, LeaseUntil: found.LeaseUntil}
		if err := putJSON(objects, []byte(found.ID), found); err != nil {
			return err
		}
		if err := putJSON(tx.Bucket(bClaims), []byte(lease), claim); err != nil {
			return err
		}
		if err := q.Delete(foundKey); err != nil {
			return err
		}
		d.stateChange(model.StateReady, model.StateLeased)
		d.claims++
		claimed = true
		return nil
	})
	if err != nil {
		return model.Claim{}, err
	}
	if !claimed {
		return model.Claim{}, ErrNotFound
	}
	return claim, nil
}

// requeue returns an object to the download queue under its original key so it
// keeps its place in arrival order instead of moving to the back.
func requeue(tx *bolt.Tx, o model.ObjectVersion) error {
	if o.QueueKey == "" {
		return nil
	}
	return tx.Bucket(bQueue).Put([]byte(o.QueueKey), []byte(o.ID))
}

// expireLease puts an object whose lease elapsed back in the queue. Startup
// recovery and the maintenance loop share it so both paths behave identically.
func expireLease(tx *bolt.Tx, o model.ObjectVersion, now time.Time, d *delta) error {
	if o.LeaseID != "" {
		if tx.Bucket(bClaims).Get([]byte(o.LeaseID)) != nil {
			if err := tx.Bucket(bClaims).Delete([]byte(o.LeaseID)); err != nil {
				return err
			}
			d.claims--
		}
	}
	o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil, o.UpdatedAt = model.StateReady, "", "", time.Time{}, now
	if err := putJSON(tx.Bucket(bObjects), []byte(o.ID), o); err != nil {
		return err
	}
	d.stateChange(model.StateLeased, model.StateReady)
	return requeue(tx, o)
}

func (s *Store) Renew(tenant, leaseID string, ttl time.Duration) (model.Claim, error) {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	var claim model.Claim
	err := s.mutateNow(func(tx *bolt.Tx, _ *delta) error {
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
	return s.mutateNow(func(tx *bolt.Tx, d *delta) error {
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
			d.stateChange(model.StateLeased, model.StateReady)
			if err := requeue(tx, o); err != nil {
				return err
			}
		}
		d.claims--
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
	err := s.mutateNow(func(tx *bolt.Tx, d *delta) error {
		alreadyDeleted = false
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
		d.stateChange(model.StateLeased, model.StateDeletePending)
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
	// Recovery and maintenance can both reach the same object, so every counter
	// change here is guarded by a presence check to stay idempotent.
	return s.mutateNow(func(tx *bolt.Tx, d *delta) error {
		ns := tx.Bucket(bNamespace)
		if id := ns.Get(nsKey(o.Tenant, o.Path)); string(id) == o.ID {
			if err := ns.Delete(nsKey(o.Tenant, o.Path)); err != nil {
				return err
			}
		}
		if o.QueueKey != "" {
			_ = tx.Bucket(bQueue).Delete([]byte(o.QueueKey))
		}
		if o.LeaseID != "" && tx.Bucket(bClaims).Get([]byte(o.LeaseID)) != nil {
			if err := tx.Bucket(bClaims).Delete([]byte(o.LeaseID)); err != nil {
				return err
			}
			d.claims--
		}
		t := model.Tombstone{ObjectID: o.ID, Tenant: o.Tenant, DeletedAt: s.now().UTC()}
		if err := putJSON(tx.Bucket(bTombstones), []byte(o.ID), t); err != nil {
			return err
		}
		objects := tx.Bucket(bObjects)
		if objects.Get([]byte(o.ID)) == nil {
			return nil
		}
		d.objects--
		d.stateChange(o.State, "")
		return objects.Delete([]byte(o.ID))
	})
}

func (s *Store) Remove(tenant, name string) error {
	clean, err := CleanPath(name)
	if err != nil {
		return err
	}
	var cleanup *model.ObjectVersion
	err = s.mutateNow(func(tx *bolt.Tx, d *delta) error {
		cleanup = nil
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
			d.stateChange(model.StateReady, model.StateDeletePending)
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
	if err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}
	if newPath == "" {
		return errors.New("invalid destination: empty path")
	}
	return s.mutateNow(func(tx *bolt.Tx, _ *delta) error {
		id := tx.Bucket(bNamespace).Get(nsKey(tenant, oldPath))
		if oldPath == newPath {
			return renameInPlace(tx, tenant, oldPath, id != nil)
		}
		if err := checkRenameDestination(tx, tenant, newPath); err != nil {
			return err
		}
		if id != nil {
			return s.renameFile(tx, tenant, oldPath, newPath, id)
		}
		return s.renameTree(tx, tenant, oldPath, newPath)
	})
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

// checkRenameDestination rejects a destination already occupied by a file, a
// directory, or a populated subtree.
func checkRenameDestination(tx *bolt.Tx, tenant, newPath string) error {
	key := nsKey(tenant, newPath)
	if tx.Bucket(bNamespace).Get(key) != nil || tx.Bucket(bDirectories).Get(key) != nil {
		return ErrConflict
	}
	if hasChildren(tx, tenant, newPath) {
		return ErrConflict
	}
	return nil
}

func (s *Store) renameFile(tx *bolt.Tx, tenant, oldPath, newPath string, id []byte) error {
	objects := tx.Bucket(bObjects)
	o, err := getJSON[model.ObjectVersion](objects, id)
	if err != nil {
		return err
	}
	o.Path, o.UpdatedAt = newPath, s.now().UTC()
	if err := putJSON(objects, id, o); err != nil {
		return err
	}
	ns := tx.Bucket(bNamespace)
	if err := ns.Put(nsKey(tenant, newPath), id); err != nil {
		return err
	}
	return ns.Delete(nsKey(tenant, oldPath))
}

func (s *Store) renameTree(tx *bolt.Tx, tenant, oldPath, newPath string) error {
	if strings.HasPrefix(newPath, oldPath+"/") {
		return ErrConflict
	}
	moves := collectTreeMoves(tx, tenant, oldPath, newPath)
	if len(moves) == 0 {
		return ErrNotFound
	}
	for _, m := range moves {
		if err := s.applyTreeMove(tx, tenant, m); err != nil {
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

func (s *Store) applyTreeMove(tx *bolt.Tx, tenant string, m treeMove) error {
	newPath := strings.TrimPrefix(string(m.newKey), tenant+"\x00")
	if m.directory {
		dirs := tx.Bucket(bDirectories)
		if err := putJSON(dirs, m.newKey, model.Entry{Path: newPath, Directory: true, UpdatedAt: s.now().UTC()}); err != nil {
			return err
		}
		return dirs.Delete(m.oldKey)
	}
	objects := tx.Bucket(bObjects)
	o, err := getJSON[model.ObjectVersion](objects, m.objectID)
	if err != nil {
		return err
	}
	o.Path, o.UpdatedAt = newPath, s.now().UTC()
	if err := putJSON(objects, m.objectID, o); err != nil {
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

// Stats is served from in-memory counters: a metrics scrape must not walk the
// whole catalog, and the container health check hits /metrics every 15 seconds.
func (s *Store) Stats() (Stats, error) { return s.count.snapshot(), nil }

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
	var stats Stats
	now := s.now().UTC()
	// This is the one full catalog scan the process performs; it doubles as the
	// source of truth for the in-memory counters that Stats reports afterwards.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		pending, finalizing, stats = nil, nil, Stats{}
		var d delta
		b := tx.Bucket(bObjects)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				continue
			}
			stats.Objects++
			switch o.State {
			case model.StateReady:
				stats.Ready++
				// A crash can leave a ready object out of the queue if it was
				// claimed and the lease reset without requeueing.
				if err := requeue(tx, o); err != nil {
					return err
				}
			case model.StateLeased:
				stats.Leased++
				if !o.LeaseUntil.After(now) {
					if err := expireLease(tx, o, now, &d); err != nil {
						return err
					}
				}
			case model.StateDeletePending:
				stats.DeletePending++
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
			stats.Uploads++
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
		cc := tx.Bucket(bClaims).Cursor()
		for k, _ := cc.First(); k != nil; k, _ = cc.Next() {
			stats.Claims++
		}
		// Fold in the lease expiries performed above.
		stats.Ready += d.ready
		stats.Leased += d.leased
		stats.Claims += d.claims
		return nil
	}); err != nil {
		return err
	}
	s.count.set(stats)
	// A single unreadable blob must not keep the service from starting: park the
	// affected record and carry on, matching how maintenancePass handles the same
	// failures at runtime.
	for _, o := range pending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := s.finishDelete(o); err != nil {
			s.log.Error("recovery could not delete object", "object", o.ID, "tenant", o.Tenant, "path", o.Path, "error", err)
		}
	}
	for _, u := range finalizing {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := s.recoverFinalizing(ctx, u); err != nil {
			s.log.Error("recovery could not finalize upload", "upload", u.ID, "tenant", u.Tenant, "path", u.Path, "error", err)
			if markErr := s.fail(u, err); markErr != nil {
				return fmt.Errorf("mark upload %s failed: %w", u.ID, markErr)
			}
		}
	}
	return nil
}

// recoverFinalizing completes an upload that stopped between fsync and catalog
// publish: either the staging file is still there and finalize can rerun, or the
// blob was already renamed and only needs publishing.
func (s *Store) recoverFinalizing(ctx context.Context, u model.Upload) error {
	if _, err := os.Stat(u.StagingPath); err == nil {
		return s.finalize(ctx, u, nil)
	}
	blob := filepath.Join(s.root, "objects", u.Tenant, u.ID+".blob")
	digest, size, err := hashFile(blob)
	if err != nil {
		return err
	}
	return s.publish(u, blob, digest, size)
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
	var expired []model.ObjectVersion
	var stale []model.Upload
	var tombstones [][]byte
	// Scan read-only. bbolt allows a single writer, so collecting the work under
	// a write transaction would block every upload's publish for the duration of
	// three full bucket walks, and most iterations change nothing.
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bObjects).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				continue
			}
			switch {
			case o.State == model.StateLeased && !o.LeaseUntil.After(now):
				expired = append(expired, o)
			case o.State == model.StateDeletePending:
				pending = append(pending, o)
			}
		}
		if partialTTL > 0 {
			uc := tx.Bucket(bUploads).Cursor()
			for _, v := uc.First(); v != nil; _, v = uc.Next() {
				var u model.Upload
				if json.Unmarshal(v, &u) != nil {
					continue
				}
				if (u.State == model.StateInterrupted || u.State == model.StateFailed) && now.Sub(u.UpdatedAt) >= partialTTL {
					stale = append(stale, u)
				}
			}
		}
		tc := tx.Bucket(bTombstones).Cursor()
		for k, v := tc.First(); k != nil; k, v = tc.Next() {
			var t model.Tombstone
			if json.Unmarshal(v, &t) == nil && now.Sub(t.DeletedAt) >= 7*24*time.Hour {
				tombstones = append(tombstones, bytes.Clone(k))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, o := range expired {
		if err = s.mutateNow(func(tx *bolt.Tx, d *delta) error {
			// Recheck under the write transaction: the lease may have been
			// renewed or the object deleted since the scan.
			current, e := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(o.ID))
			if e != nil {
				return nil
			}
			if current.State != model.StateLeased || current.LeaseUntil.After(s.now().UTC()) {
				return nil
			}
			return expireLease(tx, current, s.now().UTC(), d)
		}); err != nil {
			s.log.Warn("maintenance could not expire lease", "object", o.ID, "tenant", o.Tenant, "error", err)
		}
	}
	if len(tombstones) > 0 {
		if err = s.mutateNow(func(tx *bolt.Tx, _ *delta) error {
			tombs := tx.Bucket(bTombstones)
			for _, k := range tombstones {
				if e := tombs.Delete(k); e != nil {
					return e
				}
			}
			return nil
		}); err != nil {
			s.log.Warn("maintenance could not prune tombstones", "error", err)
		}
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
		// A failed finalize can leave behind a blob that was renamed but never published.
		if _, err := s.Object(u.ID); errors.Is(err, ErrNotFound) {
			_ = os.Remove(filepath.Join(s.root, "objects", u.Tenant, u.ID+".blob"))
		}
		_ = s.mutateNow(func(tx *bolt.Tx, d *delta) error {
			uploads := tx.Bucket(bUploads)
			if uploads.Get([]byte(u.ID)) == nil {
				return nil
			}
			d.uploads--
			return uploads.Delete([]byte(u.ID))
		})
	}
	return nil
}
