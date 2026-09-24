package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

// maxClaimScan bounds how many queue entries one claim may inspect, so a
// downloader with a narrow prefix cannot hold up the catalog.
const maxClaimScan = 20000

// ClaimOptions selects what a downloader wants.
type ClaimOptions struct {
	ClientID string
	Prefix   string
	TTL      time.Duration
	Max      int
}

// ClaimNext claims the oldest deliverable object, or returns ErrNotFound.
func (s *Store) ClaimNext(tenant, clientID, prefix string, ttl time.Duration) (model.Claim, error) {
	claims, err := s.Claim(tenant, ClaimOptions{ClientID: clientID, Prefix: prefix, TTL: ttl, Max: 1})
	if err != nil {
		return model.Claim{}, err
	}
	return claims[0], nil
}

type candidate struct {
	seq uint64
	id  string
}

// Claim leases up to opts.Max deliverable objects in queue order. The queue
// is searched in a read transaction; only the objects actually claimed take
// the write lock, and an empty queue costs no write at all.
func (s *Store) Claim(tenant string, opts ClaimOptions) ([]model.Claim, error) {
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Max <= 0 {
		opts.Max = 1
	}
	prefix, err := CleanPath(opts.Prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPath, err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		now := s.now().UTC()
		cands, err := s.findCandidates(tenant, prefix, opts.Max, now)
		if err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			return nil, ErrNotFound
		}
		var claims []model.Claim
		err = s.update(func(tx *bolt.Tx, d *delta) error {
			claims = claims[:0]
			objects := tx.Bucket(bObjects)
			for _, c := range cands {
				o, err := getJSON[model.ObjectVersion](objects, []byte(c.id))
				if err != nil || o.State != model.StateReady || o.QueueSeq != c.seq {
					// Taken by a concurrent claimer since the search.
					continue
				}
				lease, err := randomID()
				if err != nil {
					return err
				}
				if err := dequeue(tx, &o); err != nil {
					return err
				}
				o.State, o.LeaseID, o.LeaseClient, o.LeaseUntil, o.UpdatedAt = model.StateLeased, lease, opts.ClientID, now.Add(opts.TTL), now
				o.Attempts++
				claim := model.Claim{LeaseID: lease, ObjectID: o.ID, Tenant: tenant, ClientID: opts.ClientID, Path: o.Path, Size: o.Size, SHA256: o.SHA256, Version: o.Version, Attempts: o.Attempts, LeaseUntil: o.LeaseUntil, LeaseSeconds: int(opts.TTL / time.Second)}
				if err := putJSON(objects, []byte(o.ID), o); err != nil {
					return err
				}
				if err := putJSON(tx.Bucket(bClaims), []byte(lease), claim); err != nil {
					return err
				}
				if err := tx.Bucket(bLeases).Put(timeIDKey(o.LeaseUntil, o.ID), []byte(lease)); err != nil {
					return err
				}
				d.move(o, model.StateReady, model.StateLeased)
				d.claims++
				claims = append(claims, claim)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(claims) > 0 {
			return claims, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) findCandidates(tenant, prefix string, max int, now time.Time) ([]candidate, error) {
	var out []candidate
	err := s.db.View(func(tx *bolt.Tx) error {
		out = nil
		var c *bolt.Cursor
		var seek []byte
		if prefix == "" {
			c, seek = tx.Bucket(bQueue).Cursor(), []byte(tenant+"\x00")
		} else {
			c, seek = tx.Bucket(bQueueSeg).Cursor(), []byte(tenant+"\x00"+firstSegment(prefix)+"\x00")
		}
		scanned := 0
		for k, v := c.Seek(seek); k != nil && hasPrefix(k, seek); k, v = c.Next() {
			if scanned++; scanned > maxClaimScan {
				s.log.Warn("claim scan limit reached", "tenant", tenant, "prefix", prefix)
				break
			}
			visible, p := parseQueueValue(v)
			if visible.After(now) {
				continue
			}
			if prefix != "" && !pathHasPrefix(p, prefix) {
				continue
			}
			seq, id := parseTailKey(k)
			out = append(out, candidate{seq: seq, id: id})
			if len(out) >= max {
				break
			}
		}
		return nil
	})
	if prefix != "" && len(out) > 1 {
		// Entries under one first segment are only ordered within that
		// segment; restore global queue order.
		sortCandidates(out)
	}
	return out, err
}

func sortCandidates(c []candidate) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].seq < c[j-1].seq; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

// WaitForWork returns a channel closed the next time tenant's queue may have
// gained deliverable work.
func (s *Store) WaitForWork(tenant string) <-chan struct{} { return s.notify.wait(tenant) }

// NextVisible returns when the earliest delayed object of tenant becomes
// deliverable, if any is delayed.
func (s *Store) NextVisible(tenant string) (time.Time, bool) {
	var next time.Time
	found := false
	now := s.now().UTC()
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bQueue).Cursor()
		seek := []byte(tenant + "\x00")
		n := 0
		for k, v := c.Seek(seek); k != nil && hasPrefix(k, seek) && n < 1000; k, v = c.Next() {
			n++
			visible, _ := parseQueueValue(v)
			if visible.After(now) && (!found || visible.Before(next)) {
				next, found = visible, true
			}
		}
		return nil
	})
	return next, found
}

// Renew extends a lease. A zero ttl extends by the length granted at claim
// time, so a renewal can never shorten a lease by omission.
func (s *Store) Renew(tenant, leaseID string, ttl time.Duration) (model.Claim, error) {
	var claim model.Claim
	err := s.update(func(tx *bolt.Tx, _ *delta) error {
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
			return ErrLeaseMismatch
		}
		now := s.now().UTC()
		// An expired lease cannot be revived: the object may already be on
		// its way back to the queue, and a second holder must not appear.
		if o.LeaseID != leaseID || o.State != model.StateLeased || !o.LeaseUntil.After(now) {
			return ErrLeaseMismatch
		}
		if err := tx.Bucket(bLeases).Delete(timeIDKey(o.LeaseUntil, o.ID)); err != nil {
			return err
		}
		extend := ttl
		if extend <= 0 {
			extend = time.Duration(claim.LeaseSeconds) * time.Second
		}
		if extend <= 0 {
			extend = 2 * time.Minute
		}
		claim.LeaseUntil = now.Add(extend)
		o.LeaseUntil, o.UpdatedAt = claim.LeaseUntil, now
		if err := tx.Bucket(bLeases).Put(timeIDKey(o.LeaseUntil, o.ID), []byte(leaseID)); err != nil {
			return err
		}
		if err := putJSON(tx.Bucket(bClaims), []byte(leaseID), claim); err != nil {
			return err
		}
		return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
	})
	return claim, err
}

// ReleaseOptions describes why a downloader gives an object back.
type ReleaseOptions struct {
	Reason string
	// RetryAfter keeps the object invisible for this long.
	RetryAfter time.Duration
	// Permanent parks the object instead of requeueing it.
	Permanent bool
	// Uncounted returns the delivery attempt, for a downloader that is
	// shutting down rather than failing.
	Uncounted bool
}

func (s *Store) Release(tenant, leaseID string) error {
	return s.ReleaseWith(tenant, leaseID, ReleaseOptions{})
}

// ReleaseWith ends a lease early.
func (s *Store) ReleaseWith(tenant, leaseID string, opts ReleaseOptions) error {
	return s.update(func(tx *bolt.Tx, d *delta) error {
		claim, err := getJSON[model.Claim](tx.Bucket(bClaims), []byte(leaseID))
		if err != nil {
			return err
		}
		if claim.Tenant != tenant {
			return ErrLeaseMismatch
		}
		if err := tx.Bucket(bClaims).Delete([]byte(leaseID)); err != nil {
			return err
		}
		d.claims--
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(claim.ObjectID))
		if err != nil || o.LeaseID != leaseID || o.State != model.StateLeased {
			return nil
		}
		if err := tx.Bucket(bLeases).Delete(timeIDKey(o.LeaseUntil, o.ID)); err != nil {
			return err
		}
		if opts.Uncounted && o.Attempts > 0 {
			o.Attempts--
		}
		return s.afterDelivery(tx, d, o, opts)
	})
}

// afterDelivery decides where a leased object goes when its lease ends
// without a commit: deleted if the uploader retracted it, parked if it has
// failed too often, otherwise back to the tail of the queue.
func (s *Store) afterDelivery(tx *bolt.Tx, d *delta, o model.ObjectVersion, opts ReleaseOptions) error {
	now := s.now().UTC()
	o.LeaseID, o.LeaseClient, o.LeaseUntil, o.UpdatedAt = "", "", time.Time{}, now
	if opts.Reason != "" {
		o.LastError = truncate(opts.Reason, 512)
	}
	if o.Retracted {
		return s.deleteObjectTx(tx, d, o, "retracted")
	}
	if opts.Permanent || o.Attempts >= s.policyFor(o.Tenant).MaxAttempts {
		if o.LastError == "" {
			o.LastError = "delivery attempts exhausted"
		}
		o.State, o.ParkedAt = model.StateParked, now
		d.move(o, model.StateLeased, model.StateParked)
		if err := tx.Bucket(bParked).Put(parkedKey(o.Tenant, o.ParkedAt, o.ID), nil); err != nil {
			return err
		}
		s.log.Warn("object parked", "tenant", o.Tenant, "object", o.ID, "path", o.Path, "attempts", o.Attempts, "reason", o.LastError)
		return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
	}
	o.State = model.StateReady
	if err := enqueue(tx, &o, now.Add(opts.RetryAfter)); err != nil {
		return err
	}
	d.move(o, model.StateLeased, model.StateReady)
	return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Requeue returns a parked object to the tail of the queue with a fresh
// attempt budget.
func (s *Store) Requeue(tenant, objectID string) error {
	return s.update(func(tx *bolt.Tx, d *delta) error {
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(objectID))
		if err != nil || o.Tenant != tenant {
			return ErrNotFound
		}
		if o.State != model.StateParked {
			return fmt.Errorf("%w: object is %s, not parked", ErrConflict, o.State)
		}
		if err := tx.Bucket(bParked).Delete(parkedKey(o.Tenant, o.ParkedAt, o.ID)); err != nil {
			return err
		}
		o.State, o.Attempts, o.ParkedAt, o.UpdatedAt = model.StateReady, 0, time.Time{}, s.now().UTC()
		if err := enqueue(tx, &o, o.UpdatedAt); err != nil {
			return err
		}
		d.move(o, model.StateParked, model.StateReady)
		return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
	})
}

// DeleteObject removes an object that is not being delivered, by ID. Leased
// objects are retracted and deleted when their lease ends.
func (s *Store) DeleteObject(tenant, objectID, reason string) error {
	var victim *model.ObjectVersion
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		victim = nil
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(objectID))
		if err != nil || o.Tenant != tenant {
			return ErrNotFound
		}
		if o.State == model.StateLeased {
			o.Retracted = true
			if ns := tx.Bucket(bNamespace); string(ns.Get(nsKey(o.Tenant, o.Path))) == o.ID {
				if err := ns.Delete(nsKey(o.Tenant, o.Path)); err != nil {
					return err
				}
			}
			return putJSON(tx.Bucket(bObjects), []byte(o.ID), o)
		}
		victim = &o
		return s.deleteObjectTx(tx, d, o, reason)
	})
	if err == nil && victim != nil {
		s.collect(victim.ID, victim.Tenant, victim.BlobPath, victim.Size)
	}
	return err
}

func (s *Store) OpenClaim(tenant, objectID, leaseID string) (*os.File, model.ObjectVersion, error) {
	o, err := s.Object(objectID)
	if err != nil {
		return nil, o, err
	}
	if o.Tenant != tenant {
		return nil, model.ObjectVersion{}, ErrNotFound
	}
	if o.State != model.StateLeased || o.LeaseID != leaseID || !o.LeaseUntil.After(s.now()) {
		return nil, o, ErrLeaseMismatch
	}
	f, err := os.Open(o.BlobPath)
	return f, o, err
}

// Commit confirms a delivery. The object is deleted in the same transaction
// that validates the lease and digest; the blob is unlinked right after and
// its garbage-collection entry is cleared lazily. A repeated commit of an
// already deleted object reports (false, nil).
func (s *Store) Commit(tenant, objectID, leaseID, digest string, size int64) (bool, error) {
	var o model.ObjectVersion
	var outcome error
	alreadyDeleted := false
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		alreadyDeleted, outcome = false, nil
		if tombstone, err := getJSON[model.Tombstone](tx.Bucket(bTombstones), []byte(objectID)); err == nil {
			if tombstone.Tenant != tenant {
				outcome = ErrNotFound
				return nil
			}
			alreadyDeleted = true
			return nil
		}
		var err error
		o, err = getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(objectID))
		if err != nil || o.Tenant != tenant {
			outcome = ErrNotFound
			return nil
		}
		if o.LeaseID != leaseID || o.State != model.StateLeased {
			outcome = ErrLeaseMismatch
			return nil
		}
		if o.Size != size || !strings.EqualFold(o.SHA256, digest) {
			outcome = ErrConflict
			return nil
		}
		return s.deleteObjectTx(tx, d, o, "committed")
	})
	if err != nil {
		return false, err
	}
	if outcome != nil {
		return false, outcome
	}
	if alreadyDeleted {
		return false, nil
	}
	s.collect(o.ID, o.Tenant, o.BlobPath, o.Size)
	return true, nil
}

// deleteObjectTx removes o and every index entry pointing at it, leaves a
// tombstone for idempotent commits, and schedules its blob for unlinking.
func (s *Store) deleteObjectTx(tx *bolt.Tx, d *delta, o model.ObjectVersion, reason string) error {
	now := s.now().UTC()
	ns := tx.Bucket(bNamespace)
	if string(ns.Get(nsKey(o.Tenant, o.Path))) == o.ID {
		if err := ns.Delete(nsKey(o.Tenant, o.Path)); err != nil {
			return err
		}
	}
	if err := dequeue(tx, &o); err != nil {
		return err
	}
	if o.LeaseID != "" {
		if tx.Bucket(bClaims).Get([]byte(o.LeaseID)) != nil {
			if err := tx.Bucket(bClaims).Delete([]byte(o.LeaseID)); err != nil {
				return err
			}
			d.claims--
		}
		_ = tx.Bucket(bLeases).Delete(timeIDKey(o.LeaseUntil, o.ID))
	}
	switch o.State {
	case model.StateParked:
		_ = tx.Bucket(bParked).Delete(parkedKey(o.Tenant, o.ParkedAt, o.ID))
	case model.StateHeld:
		_ = tx.Bucket(bHeld).Delete(timeIDKey(o.CreatedAt, o.ID))
	}
	t := model.Tombstone{ObjectID: o.ID, Tenant: o.Tenant, Reason: reason, DeletedAt: now}
	if err := putJSON(tx.Bucket(bTombstones), []byte(o.ID), t); err != nil {
		return err
	}
	if err := tx.Bucket(bTombTimes).Put(timeIDKey(now, o.ID), nil); err != nil {
		return err
	}
	if err := putJSON(tx.Bucket(bGC), []byte(o.ID), gcEntry{Tenant: o.Tenant, Blob: o.BlobPath, Size: o.Size}); err != nil {
		return err
	}
	d.gc++
	objects := tx.Bucket(bObjects)
	if objects.Get([]byte(o.ID)) == nil {
		return nil
	}
	state := o.State
	if state == model.StateDeletePending {
		state = ""
		o.Size = 0 // legacy records were never counted as live bytes by state
	}
	d.move(o, state, "")
	return objects.Delete([]byte(o.ID))
}

// collect unlinks a deleted object's blob. The catalog already records the
// deletion, so a crash here only leaves a garbage-collection entry behind.
func (s *Store) collect(id, tenant, blob string, size int64) {
	if blob == "" {
		blob = s.blobPath(tenant, id)
	}
	if err := os.Remove(blob); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("could not remove blob", "object", id, "blob", blob, "error", err)
		return
	}
	_ = syncDir(filepath.Dir(blob))
	if s.gate != nil {
		s.gate.ObserveDelete(size)
	}
	s.gcMu.Lock()
	s.gcDone = append(s.gcDone, []byte(id))
	s.gcMu.Unlock()
}

// flushGC clears the garbage-collection entries of blobs already unlinked, in
// one transaction for many deletions.
func (s *Store) flushGC() {
	s.gcMu.Lock()
	done := s.gcDone
	s.gcDone = nil
	s.gcMu.Unlock()
	if len(done) == 0 {
		return
	}
	if err := s.update(func(tx *bolt.Tx, d *delta) error {
		d.gc = 0
		b := tx.Bucket(bGC)
		for _, id := range done {
			if b.Get(id) != nil {
				if err := b.Delete(id); err != nil {
					return err
				}
				d.gc--
			}
		}
		return nil
	}); err != nil {
		s.gcMu.Lock()
		s.gcDone = append(s.gcDone, done...)
		s.gcMu.Unlock()
	}
}

// ListParked returns a tenant's parked (dead-lettered) objects, oldest first.
func (s *Store) ListParked(tenant string, limit int) ([]model.ObjectVersion, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []model.ObjectVersion
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bParked).Cursor()
		seek := []byte(tenant + "\x00")
		for k, _ := c.Seek(seek); k != nil && hasPrefix(k, seek) && len(out) < limit; k, _ = c.Next() {
			_, id := parseTailKey(k)
			if o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id)); err == nil {
				out = append(out, o)
			}
		}
		return nil
	})
	return out, err
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

// UpdateObject changes an object's protocol metadata. It must not be used to
// change state or path.
func (s *Store) UpdateObject(id string, update func(*model.ObjectVersion) error) error {
	return s.update(func(tx *bolt.Tx, _ *delta) error {
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
		if err != nil {
			return err
		}
		state, p := o.State, o.Path
		if err := update(&o); err != nil {
			return err
		}
		if o.State != state || o.Path != p {
			return errors.New("UpdateObject cannot change state or path")
		}
		o.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bObjects), []byte(id), o)
	})
}

// OldestReady returns the creation time of the tenant's oldest deliverable
// object, for queue-age monitoring.
func (s *Store) OldestReady(tenant string) (time.Time, bool) {
	var at time.Time
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bQueue).Cursor()
		seek := []byte(tenant + "\x00")
		k, _ := c.Seek(seek)
		if k == nil || !hasPrefix(k, seek) {
			return nil
		}
		_, id := parseTailKey(k)
		if o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id)); err == nil {
			at, found = o.CreatedAt, true
		}
		return nil
	})
	return at, found
}

// PurgeTenant deletes every object and partial upload of a tenant, for an
// account being removed. Objects being delivered are retracted and deleted when
// their lease ends. It walks the whole catalog and is meant for rare admin use.
func (s *Store) PurgeTenant(tenant string) (int, error) {
	var ids []string
	var uploads []string
	if err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bObjects).ForEach(func(k, v []byte) error {
			if o, err := decodeObject(v); err == nil && o.Tenant == tenant {
				ids = append(ids, string(k))
			}
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bUploads).ForEach(func(k, v []byte) error {
			if u, err := decodeUpload(v); err == nil && u.Tenant == tenant && (u.State == model.StateInterrupted || u.State == model.StateFailed) {
				uploads = append(uploads, string(k))
			}
			return nil
		})
	}); err != nil {
		return 0, err
	}
	removed := 0
	for _, id := range ids {
		if err := s.DeleteObject(tenant, id, "purged"); err != nil && !errors.Is(err, ErrNotFound) {
			return removed, err
		}
		removed++
	}
	for _, id := range uploads {
		if err := s.reclaimUpload(id, s.now().Add(time.Hour)); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
