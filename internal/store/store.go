// Package store is the transfer catalog: immutable object versions on disk,
// indexed by a bbolt database that also holds the upload sessions, the
// delivery queue and the leases handed to downloaders.
//
// The package is split by responsibility:
//
//	store.go     lifecycle, write transactions, counters
//	schema.go    bucket layout, key encodings, index rebuild and migration
//	upload.go    upload sessions: base selection, coverage, digest, publish
//	delivery.go  claim, renew, release, commit, parking
//	namespace.go the uploader-facing file tree: stat, list, rename, remove
//	maintain.go  crash recovery and background maintenance
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	ErrDraining      = errors.New("server is shutting down; retry shortly")
	ErrQuota         = errors.New("account storage quota exceeded")
	ErrBusy          = errors.New("object is being delivered and cannot be renamed")
	ErrIsDirectory   = errors.New("path is a directory")
	ErrNotDirectory  = errors.New("a parent of the path is a file")
	ErrInvalidOffset = errors.New("write offset does not continue any existing upload")
	ErrIncomplete    = errors.New("upload is incomplete: bytes were not written contiguously")
	ErrInvalidPath   = errors.New("invalid path")
)

// Gate is the capacity controller as the store sees it.
type Gate interface {
	AdmitUpload() error
	AcquireUpload(context.Context, string) (func(), error)
	WaitN(context.Context, string, int) error
	Reserve(int64) (func(), bool)
	CheckCritical() error
	ObserveDelete(int64)
}

// Policy is the per-tenant behaviour the store applies.
type Policy struct {
	// Supersede drops undelivered older versions when a path is uploaded
	// again. Without it every version is delivered.
	Supersede      bool
	HoldPatterns   []string
	PublishDelay   time.Duration
	MaxAttempts    int
	MaxStoredBytes int64
}

// DefaultPolicy is used for tenants the policy source does not know.
func DefaultPolicy() Policy {
	return Policy{Supersede: true, HoldPatterns: []string{"*.filepart", "*.partial", "*.tmp"}, MaxAttempts: 10}
}

type Options struct {
	Gate         Gate
	Log          *slog.Logger
	Policy       func(tenant string) Policy
	TombstoneTTL time.Duration
	Now          func() time.Time
}

type Store struct {
	root         string
	db           *bolt.DB
	gate         Gate
	log          *slog.Logger
	now          func() time.Time
	policy       func(string) Policy
	tombstoneTTL time.Duration

	count    counters
	inflight atomic.Int64
	writers  atomic.Int64
	draining atomic.Bool
	notify   notifier

	gcMu   sync.Mutex
	gcDone [][]byte
}

// Open opens (creating if needed) the catalog under root and recovers from any
// crash. gate may be nil, which disables capacity control.
func Open(root string, gate Gate, log *slog.Logger) (*Store, error) {
	return OpenWithOptions(root, Options{Gate: gate, Log: log})
}

func OpenWithOptions(root string, opts Options) (*Store, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.TombstoneTTL <= 0 {
		opts.TombstoneTTL = 7 * 24 * time.Hour
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
	// Concurrent writers are coalesced into one commit; keep the window short
	// because every claim and commit is on a client's critical path.
	db.MaxBatchDelay = 2 * time.Millisecond
	s := &Store{root: root, db: db, gate: opts.Gate, log: opts.Log, now: opts.Now, policy: opts.Policy, tombstoneTTL: opts.TombstoneTTL}
	s.notify.init()
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.Recover(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// SetPolicy installs the per-tenant policy source.
func (s *Store) SetPolicy(fn func(string) Policy) { s.policy = fn }

func (s *Store) policyFor(tenant string) Policy {
	if s.policy == nil {
		return DefaultPolicy()
	}
	p := s.policy(tenant)
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultPolicy().MaxAttempts
	}
	return p
}

func (s *Store) Close() error {
	s.flushGC()
	return s.db.Close()
}

func (s *Store) Root() string { return s.root }

// Drain stops new uploads from starting and wakes long-polling claimers so
// they can return. Uploads already open may finish.
func (s *Store) Drain() {
	s.draining.Store(true)
	s.notify.signalAll()
}

// Draining reports whether Drain was called.
func (s *Store) Draining() bool { return s.draining.Load() }

// InFlight returns the number of open upload handles.
func (s *Store) InFlight() int64 { return s.inflight.Load() }

// WaitIdle blocks until no upload handle is open or ctx ends.
func (s *Store) WaitIdle(ctx context.Context) error {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for s.inflight.Load() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// AllowNewUpload reports whether the capacity gate currently admits uploads.
func (s *Store) AllowNewUpload() bool {
	return !s.draining.Load() && (s.gate == nil || s.gate.AdmitUpload() == nil)
}

// AdmitUpload returns why a new upload for tenant would be refused, or nil.
func (s *Store) AdmitUpload(tenant string) error {
	if s.draining.Load() {
		return ErrDraining
	}
	if s.gate != nil {
		if err := s.gate.AdmitUpload(); err != nil {
			return fmt.Errorf("%w: %w", ErrUploadBlocked, err)
		}
	}
	if limit := s.policyFor(tenant).MaxStoredBytes; limit > 0 && s.count.tenant(tenant).Bytes >= limit {
		return ErrQuota
	}
	return nil
}

// AcquireSlot takes one of the tenant's concurrent-upload slots for work that
// does not go through an UploadHandle, such as an S3 multipart part.
func (s *Store) AcquireSlot(ctx context.Context, tenant string) (func(), error) {
	if s.draining.Load() {
		return nil, ErrDraining
	}
	if s.gate == nil {
		return func() {}, nil
	}
	return s.gate.AcquireUpload(ctx, tenant)
}

func (s *Store) WaitUpload(ctx context.Context, tenant string, n int) error {
	if s.gate == nil {
		return nil
	}
	return s.gate.WaitN(ctx, tenant, n)
}

// HasRoomFor reports whether n additional bytes fit under the watermarks.
func (s *Store) HasRoomFor(n int64) bool {
	release, ok := s.Reserve(n)
	if ok {
		release()
	}
	return ok
}

// Reserve claims headroom for a server-side write of n bytes.
func (s *Store) Reserve(n int64) (func(), bool) {
	if s.gate == nil {
		return func() {}, true
	}
	return s.gate.Reserve(n)
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

// update runs fn in a write transaction and applies its counter delta only
// after the transaction commits. When other writers are active the call joins
// a bbolt batch, so concurrent uploads, claims and commits share one fsync; a
// lone writer commits immediately instead of waiting out the batch window.
//
// A batched closure may be replayed, so fn must reset any state it reports to
// the caller; the delta is reset on every attempt for that reason. Expected
// business outcomes should be reported through captured variables rather than
// errors, because an error makes bbolt retry the whole batch one by one.
func (s *Store) update(fn func(tx *bolt.Tx, d *delta) error) error {
	n := s.writers.Add(1)
	defer s.writers.Add(-1)
	run := s.db.Update
	if n > 1 {
		run = s.db.Batch
	}
	var d delta
	if err := run(func(tx *bolt.Tx) error {
		d = delta{}
		return fn(tx, &d)
	}); err != nil {
		return err
	}
	s.count.apply(d)
	for t := range d.touched {
		s.notify.signal(t)
	}
	return nil
}

// notifier wakes long-polling claimers when a tenant's queue may have work.
type notifier struct {
	mu    sync.Mutex
	chans map[string]chan struct{}
}

func (n *notifier) init() { n.chans = map[string]chan struct{}{} }

func (n *notifier) wait(tenant string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := n.chans[tenant]
	if ch == nil {
		ch = make(chan struct{})
		n.chans[tenant] = ch
	}
	return ch
}

func (n *notifier) signalAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for t, ch := range n.chans {
		close(ch)
		delete(n.chans, t)
	}
}

func (n *notifier) signal(tenant string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ch := n.chans[tenant]; ch != nil {
		close(ch)
		delete(n.chans, tenant)
	}
}

// Stats is the catalog's state distribution, kept in memory so a metrics
// scrape never walks the catalog.
type Stats struct {
	Objects, Ready, Leased, Held, Parked int
	// DeletePending counts blobs whose objects are gone but whose files are
	// still queued for garbage collection.
	DeletePending int
	Uploads       int
	Claims        int
	Bytes         int64
}

// TenantStats is Stats for one tenant's objects.
type TenantStats struct {
	Objects, Ready, Leased, Held, Parked int
	Bytes                                int64
}

type counters struct {
	mu      sync.Mutex
	s       Stats
	tenants map[string]TenantStats
}

func (c *counters) set(s Stats, tenants map[string]TenantStats) {
	c.mu.Lock()
	c.s, c.tenants = s, tenants
	c.mu.Unlock()
}

func (c *counters) snapshot() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s
}

func (c *counters) tenant(id string) TenantStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tenants[id]
}

func (c *counters) allTenants() map[string]TenantStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]TenantStats, len(c.tenants))
	for k, v := range c.tenants {
		out[k] = v
	}
	return out
}

func (c *counters) apply(d delta) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tenants == nil {
		c.tenants = map[string]TenantStats{}
	}
	c.s.Uploads += d.uploads
	c.s.Claims += d.claims
	c.s.DeletePending += d.gc
	for id, td := range d.tenants {
		t := c.tenants[id]
		t.Objects += td.Objects
		t.Ready += td.Ready
		t.Leased += td.Leased
		t.Held += td.Held
		t.Parked += td.Parked
		t.Bytes += td.Bytes
		c.tenants[id] = t
		c.s.Objects += td.Objects
		c.s.Ready += td.Ready
		c.s.Leased += td.Leased
		c.s.Held += td.Held
		c.s.Parked += td.Parked
		c.s.Bytes += td.Bytes
	}
}

// delta accumulates counter changes made inside a write transaction. It is only
// applied once the transaction commits, so a rollback cannot skew the counters.
type delta struct {
	uploads, claims, gc int
	tenants             map[string]*TenantStats
	// touched lists tenants whose queue gained work, to wake long pollers.
	touched map[string]bool
}

func (d *delta) wake(tenant string) {
	if d.touched == nil {
		d.touched = map[string]bool{}
	}
	d.touched[tenant] = true
}

func bump(t *TenantStats, st model.State, n int) {
	switch st {
	case model.StateReady:
		t.Ready += n
	case model.StateLeased:
		t.Leased += n
	case model.StateHeld:
		t.Held += n
	case model.StateParked:
		t.Parked += n
	}
}

// move records an object changing state. An empty from means the object is
// being created; an empty to means it is being removed.
func (d *delta) move(o model.ObjectVersion, from, to model.State) {
	if d.tenants == nil {
		d.tenants = map[string]*TenantStats{}
	}
	t := d.tenants[o.Tenant]
	if t == nil {
		t = &TenantStats{}
		d.tenants[o.Tenant] = t
	}
	if from == "" {
		t.Objects++
		t.Bytes += o.Size
	} else {
		bump(t, from, -1)
	}
	if to == "" {
		t.Objects--
		t.Bytes -= o.Size
	} else {
		bump(t, to, 1)
	}
	if to == model.StateReady {
		d.wake(o.Tenant)
	}
}

// Stats returns the in-memory counters.
func (s *Store) Stats() (Stats, error) { return s.count.snapshot(), nil }

// TenantStats returns the in-memory counters for every tenant with objects.
func (s *Store) TenantStats() map[string]TenantStats { return s.count.allTenants() }

func decodeObject(v []byte) (model.ObjectVersion, error) {
	var o model.ObjectVersion
	err := json.Unmarshal(v, &o)
	return o, err
}

func decodeUpload(v []byte) (model.Upload, error) {
	var u model.Upload
	err := json.Unmarshal(v, &u)
	return u, err
}
