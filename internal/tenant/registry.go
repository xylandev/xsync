// Package tenant holds the live account table. Every protocol front end and the
// capacity controller read accounts through a Registry instead of copying the
// list at startup, so account changes apply without restarting the server.
package tenant

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xylandev/xsync/internal/config"
)

// Snapshot is an immutable, indexed view of the accounts at one point in time.
type Snapshot struct {
	all      []config.Tenant
	byID     map[string]*config.Tenant
	bySFTP   map[string]*config.Tenant
	byFTP    map[string]*config.Tenant
	byAccess map[string]*config.Tenant
	byBucket map[string]*config.Tenant
	byAPIKey map[string]*config.Tenant
}

func newSnapshot(list []config.Tenant) *Snapshot {
	s := &Snapshot{
		all:      append([]config.Tenant(nil), list...),
		byID:     map[string]*config.Tenant{},
		bySFTP:   map[string]*config.Tenant{},
		byFTP:    map[string]*config.Tenant{},
		byAccess: map[string]*config.Tenant{},
		byBucket: map[string]*config.Tenant{},
		byAPIKey: map[string]*config.Tenant{},
	}
	for i := range s.all {
		t := &s.all[i]
		s.byID[t.ID] = t
		if t.SFTPUser != "" {
			s.bySFTP[t.SFTPUser] = t
		}
		if t.FTPUser != "" {
			s.byFTP[t.FTPUser] = t
		}
		if t.S3AccessKey != "" {
			s.byAccess[t.S3AccessKey] = t
		}
		if t.S3Bucket != "" {
			s.byBucket[t.S3Bucket] = t
		}
		if t.APIKeySHA256 != "" {
			s.byAPIKey[strings.ToLower(t.APIKeySHA256)] = t
		}
	}
	return s
}

// All returns every account, including disabled ones.
func (s *Snapshot) All() []config.Tenant { return s.all }

// Get returns an account by ID, including disabled ones.
func (s *Snapshot) Get(id string) (config.Tenant, bool) {
	t, ok := s.byID[id]
	if !ok {
		return config.Tenant{}, false
	}
	return *t, true
}

// Active reports whether id names an enabled account.
func (s *Snapshot) Active(id string) bool {
	t, ok := s.byID[id]
	return ok && !t.Disabled
}

func active(t *config.Tenant, ok bool) (config.Tenant, bool) {
	if !ok || t.Disabled {
		return config.Tenant{}, false
	}
	return *t, true
}

// BySFTPUser returns the enabled account that owns an SFTP user name.
func (s *Snapshot) BySFTPUser(user string) (config.Tenant, bool) {
	t, ok := s.bySFTP[user]
	return active(t, ok)
}

// ByFTPUser returns the enabled account that owns an FTP user name.
func (s *Snapshot) ByFTPUser(user string) (config.Tenant, bool) {
	t, ok := s.byFTP[user]
	return active(t, ok)
}

// ByAccessKey returns the enabled account that owns an S3 access key.
func (s *Snapshot) ByAccessKey(key string) (config.Tenant, bool) {
	t, ok := s.byAccess[key]
	return active(t, ok)
}

// ByBucket returns the enabled account that owns an S3 bucket.
func (s *Snapshot) ByBucket(bucket string) (config.Tenant, bool) {
	t, ok := s.byBucket[bucket]
	return active(t, ok)
}

// ByAPIKey authenticates a download API key. The key is looked up by its
// SHA-256, which is what the account table stores, and the match is confirmed
// with a constant-time comparison.
func (s *Snapshot) ByAPIKey(key string) (config.Tenant, bool) {
	if key == "" {
		return config.Tenant{}, false
	}
	sum := sha256.Sum256([]byte(key))
	digest := hex.EncodeToString(sum[:])
	t, ok := s.byAPIKey[digest]
	if !ok || subtle.ConstantTimeCompare([]byte(strings.ToLower(t.APIKeySHA256)), []byte(digest)) != 1 {
		return config.Tenant{}, false
	}
	return active(t, ok)
}

// Registry publishes account snapshots to concurrent readers.
type Registry struct {
	current atomic.Pointer[Snapshot]
	mu      sync.Mutex
	subs    []func(*Snapshot)
}

func NewRegistry(list []config.Tenant) *Registry {
	r := &Registry{}
	r.current.Store(newSnapshot(list))
	return r
}

// Load returns the current snapshot. Callers should load once per operation so
// that one request sees a consistent account table.
func (r *Registry) Load() *Snapshot { return r.current.Load() }

// Replace installs a new account list and notifies subscribers.
func (r *Registry) Replace(list []config.Tenant) {
	snap := newSnapshot(list)
	r.current.Store(snap)
	r.mu.Lock()
	subs := append([]func(*Snapshot){}, r.subs...)
	r.mu.Unlock()
	for _, fn := range subs {
		fn(snap)
	}
}

// Subscribe registers fn to run after every Replace.
func (r *Registry) Subscribe(fn func(*Snapshot)) {
	r.mu.Lock()
	r.subs = append(r.subs, fn)
	r.mu.Unlock()
}
