package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

// Recover brings the catalog to a consistent state after a crash: uploads that
// were streaming become resumable partials, uploads caught between fsync and
// publish are finished, and blobs of committed deletions are unlinked. Lease
// expiry is left to the maintenance loop, which handles it through the lease
// index. A single unrecoverable upload is parked as FAILED instead of keeping
// the service from starting.
func (s *Store) Recover(ctx context.Context) error {
	var finalizing []model.Upload
	now := s.now().UTC()
	if err := s.update(func(tx *bolt.Tx, _ *delta) error {
		finalizing = nil
		uploads := tx.Bucket(bUploads)
		var interrupted []model.Upload
		if err := uploads.ForEach(func(_, v []byte) error {
			var u model.Upload
			if json.Unmarshal(v, &u) != nil {
				return nil
			}
			switch u.State {
			case model.StateFinalizing:
				finalizing = append(finalizing, u)
			case model.StateUploading:
				interrupted = append(interrupted, u)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, u := range interrupted {
			u.State, u.UpdatedAt, u.Error = model.StateInterrupted, now, "server restarted during upload"
			if err := putJSON(uploads, []byte(u.ID), u); err != nil {
				return err
			}
			if err := tx.Bucket(bStale).Put(timeIDKey(u.UpdatedAt, u.ID), nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := s.recount(); err != nil {
		return err
	}
	for _, u := range finalizing {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := s.recoverFinalizing(u); err != nil {
			s.log.Error("recovery could not finalize upload", "upload", u.ID, "tenant", u.Tenant, "path", u.Path, "error", err)
		}
	}
	s.sweepGC()
	return nil
}

// recoverFinalizing completes an upload that stopped between fsync and catalog
// publish: either the staging file is still there and finalize can rerun, or the
// blob was already renamed and only needs publishing.
func (s *Store) recoverFinalizing(u model.Upload) error {
	if _, err := os.Stat(u.StagingPath); err == nil {
		return s.finalize(u, nil, nil)
	}
	blob := s.blobPath(u.Tenant, u.ID)
	digest, size, err := hashFile(blob)
	if err != nil {
		return s.fail(u, err)
	}
	if err := s.publish(u, blob, digest, size, nil); err != nil {
		return s.fail(u, err)
	}
	return nil
}

// MaintainOptions tunes the background loops.
type MaintainOptions struct {
	// Interval is the slow pass: expired partials, held files, tombstones.
	Interval time.Duration
	// PartialTTL is how long interrupted uploads and held files are kept.
	PartialTTL time.Duration
	// PressureTTL replaces PartialTTL while Pressure reports true, so
	// abandoned partials give way when the disk is filling up.
	PressureTTL time.Duration
	Pressure    func() bool
	// ReconcileEvery is how often orphaned files on disk are looked for.
	ReconcileEvery time.Duration
}

// Maintain runs the background loops until ctx ends. Lease expiry and
// garbage-collection flushing run every second through their indexes, so a
// lapsed lease is requeued promptly without scanning the catalog.
func (s *Store) Maintain(ctx context.Context, interval, partialTTL time.Duration) {
	s.MaintainWith(ctx, MaintainOptions{Interval: interval, PartialTTL: partialTTL})
}

func (s *Store) MaintainWith(ctx context.Context, opts MaintainOptions) {
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.ReconcileEvery <= 0 {
		opts.ReconcileEvery = time.Hour
	}
	fast := time.NewTicker(time.Second)
	slow := time.NewTicker(opts.Interval)
	defer fast.Stop()
	defer slow.Stop()
	lastReconcile := s.now()
	for {
		select {
		case <-ctx.Done():
			s.flushGC()
			return
		case <-fast.C:
			if err := s.ExpireLeases(); err != nil {
				s.log.Warn("lease expiry failed", "error", err)
			}
			s.flushGC()
		case <-slow.C:
			ttl := opts.PartialTTL
			if opts.Pressure != nil && opts.Pressure() && opts.PressureTTL > 0 && opts.PressureTTL < ttl {
				ttl = opts.PressureTTL
			}
			if err := s.maintenancePass(ctx, ttl); err != nil {
				s.log.Warn("maintenance pass failed", "error", err)
			}
			if s.now().Sub(lastReconcile) >= opts.ReconcileEvery {
				lastReconcile = s.now()
				if err := s.Reconcile(ctx, opts.PartialTTL); err != nil {
					s.log.Warn("reconcile failed", "error", err)
				}
			}
		}
	}
}

// ExpireLeases requeues every object whose lease has lapsed.
func (s *Store) ExpireLeases() error {
	now := s.now().UTC()
	var due []string
	if err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bLeases).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			at, id := parseTimeIDKey(k)
			if at.After(now) {
				break
			}
			due = append(due, id)
		}
		return nil
	}); err != nil || len(due) == 0 {
		return err
	}
	var retracted []model.ObjectVersion
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		retracted = retracted[:0]
		for _, id := range due {
			o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
			if err != nil || o.State != model.StateLeased || o.LeaseUntil.After(now) {
				continue
			}
			if err := tx.Bucket(bLeases).Delete(timeIDKey(o.LeaseUntil, o.ID)); err != nil {
				return err
			}
			if tx.Bucket(bClaims).Get([]byte(o.LeaseID)) != nil {
				if err := tx.Bucket(bClaims).Delete([]byte(o.LeaseID)); err != nil {
					return err
				}
				d.claims--
			}
			if o.Retracted {
				retracted = append(retracted, o)
			}
			if err := s.afterDelivery(tx, d, o, ReleaseOptions{Reason: "lease expired"}); err != nil {
				return err
			}
		}
		return nil
	})
	for _, o := range retracted {
		s.collect(o.ID, o.Tenant, o.BlobPath, o.Size)
	}
	return err
}

func (s *Store) maintenancePass(ctx context.Context, partialTTL time.Duration) error {
	now := s.now().UTC()
	if err := s.ExpireLeases(); err != nil {
		return err
	}
	var stale, held, tombs []string
	if err := s.db.View(func(tx *bolt.Tx) error {
		collect := func(b []byte, cutoff time.Time, into *[]string) {
			c := tx.Bucket(b).Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				at, id := parseTimeIDKey(k)
				if !at.Before(cutoff) {
					break
				}
				*into = append(*into, id)
			}
		}
		if partialTTL > 0 {
			collect(bStale, now.Add(-partialTTL), &stale)
			collect(bHeld, now.Add(-partialTTL), &held)
		}
		collect(bTombTimes, now.Add(-s.tombstoneTTL), &tombs)
		return nil
	}); err != nil {
		return err
	}
	var errs []error
	for _, id := range stale {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.reclaimUpload(id, now.Add(-partialTTL)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, id := range held {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A held temporary file that was never renamed is an abandoned
		// transfer, the same as an interrupted upload.
		if err := s.deleteIf(id, func(o model.ObjectVersion) bool {
			return o.State == model.StateHeld && o.CreatedAt.Before(now.Add(-partialTTL))
		}, "held-expired"); err != nil {
			errs = append(errs, err)
		}
	}
	if len(tombs) > 0 {
		if err := s.update(func(tx *bolt.Tx, _ *delta) error {
			for _, id := range tombs {
				t, err := getJSON[model.Tombstone](tx.Bucket(bTombstones), []byte(id))
				if err == nil {
					_ = tx.Bucket(bTombTimes).Delete(timeIDKey(t.DeletedAt, id))
				}
				if err := tx.Bucket(bTombstones).Delete([]byte(id)); err != nil {
					return err
				}
			}
			// Index entries whose tombstone was already gone.
			c := tx.Bucket(bTombTimes).Cursor()
			cutoff := now.Add(-s.tombstoneTTL)
			var drop [][]byte
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				at, _ := parseTimeIDKey(k)
				if !at.Before(cutoff) {
					break
				}
				drop = append(drop, append([]byte(nil), k...))
			}
			for _, k := range drop {
				if err := tx.Bucket(bTombTimes).Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			errs = append(errs, err)
		}
	}
	s.sweepGC()
	return errors.Join(errs...)
}

// reclaimUpload deletes an interrupted or failed upload older than cutoff. The
// state is rechecked in the write transaction, so an upload resumed since the
// scan is left alone.
func (s *Store) reclaimUpload(id string, cutoff time.Time) error {
	var victim *model.Upload
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		victim = nil
		u, err := getJSON[model.Upload](tx.Bucket(bUploads), []byte(id))
		if err != nil {
			return nil
		}
		if (u.State != model.StateInterrupted && u.State != model.StateFailed) || !u.UpdatedAt.Before(cutoff) {
			return nil
		}
		_ = tx.Bucket(bStale).Delete(timeIDKey(u.UpdatedAt, u.ID))
		_ = tx.Bucket(bUploadPaths).Delete(uploadPathKey(u.Tenant, u.Path, u.ID))
		d.uploads--
		victim = &u
		return tx.Bucket(bUploads).Delete([]byte(id))
	})
	if err == nil && victim != nil {
		_ = os.Remove(victim.StagingPath)
		if _, e := s.Object(victim.ID); errors.Is(e, ErrNotFound) {
			_ = os.Remove(s.blobPath(victim.Tenant, victim.ID))
		}
	}
	return err
}

func (s *Store) deleteIf(id string, pred func(model.ObjectVersion) bool, reason string) error {
	var victim *model.ObjectVersion
	err := s.update(func(tx *bolt.Tx, d *delta) error {
		victim = nil
		o, err := getJSON[model.ObjectVersion](tx.Bucket(bObjects), []byte(id))
		if err != nil || !pred(o) {
			return nil
		}
		victim = &o
		return s.deleteObjectTx(tx, d, o, reason)
	})
	if err == nil && victim != nil {
		s.collect(victim.ID, victim.Tenant, victim.BlobPath, victim.Size)
	}
	return err
}

// sweepGC unlinks blobs of deleted objects that a crash left behind.
func (s *Store) sweepGC() {
	var pending []struct {
		id string
		e  gcEntry
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bGC).ForEach(func(k, v []byte) error {
			var e gcEntry
			if json.Unmarshal(v, &e) == nil {
				pending = append(pending, struct {
					id string
					e  gcEntry
				}{string(k), e})
			}
			return nil
		})
	})
	for _, p := range pending {
		s.collect(p.id, p.e.Tenant, p.e.Blob, 0)
	}
	s.flushGC()
}

// Reconcile removes files on disk that no catalog record refers to: staging
// files of uploads that no longer exist and blobs of objects that were never
// published. Only files older than minAge are touched, so an upload that is
// being created right now is never mistaken for an orphan.
func (s *Store) Reconcile(ctx context.Context, minAge time.Duration) error {
	cutoff := s.now().Add(-minAge)
	var removed atomic.Int64
	check := func(root string, known func(tenant, id string) bool) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel, _ := filepath.Rel(root, p)
			tenant, file, ok := strings.Cut(filepath.ToSlash(rel), "/")
			if !ok || strings.Contains(file, "/") || tenant == "s3-multipart" {
				return nil
			}
			id := strings.TrimSuffix(strings.TrimSuffix(file, ".partial"), ".blob")
			if id == file {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().After(cutoff) {
				return nil
			}
			if !known(tenant, id) {
				if os.Remove(p) == nil {
					removed.Add(1)
					s.log.Warn("removed orphaned file", "path", p)
				}
			}
			return nil
		})
	}
	knownUpload := func(_, id string) bool {
		found := true
		_ = s.db.View(func(tx *bolt.Tx) error {
			found = tx.Bucket(bUploads).Get([]byte(id)) != nil
			return nil
		})
		return found
	}
	knownObject := func(_, id string) bool {
		found := true
		_ = s.db.View(func(tx *bolt.Tx) error {
			found = tx.Bucket(bObjects).Get([]byte(id)) != nil || tx.Bucket(bUploads).Get([]byte(id)) != nil || tx.Bucket(bGC).Get([]byte(id)) != nil
			return nil
		})
		return found
	}
	if err := check(filepath.Join(s.root, "staging"), knownUpload); err != nil {
		return err
	}
	if err := check(filepath.Join(s.root, "objects"), knownObject); err != nil {
		return err
	}
	if n := removed.Load(); n > 0 {
		s.log.Info("reconcile removed orphaned files", "count", n)
	}
	return nil
}

// StagingBytes reports the bytes held by open, interrupted and failed uploads.
func (s *Store) StagingBytes() int64 {
	var total int64
	_ = filepath.WalkDir(filepath.Join(s.root, "staging"), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// Check verifies that the catalog's indexes agree with its primary records
// and that every published blob exists. It reads only.
func (s *Store) Check() ([]string, error) {
	var problems []string
	err := s.db.View(func(tx *bolt.Tx) error {
		objects := tx.Bucket(bObjects)
		return objects.ForEach(func(k, v []byte) error {
			var o model.ObjectVersion
			if err := json.Unmarshal(v, &o); err != nil {
				problems = append(problems, fmt.Sprintf("object %s: undecodable record", k))
				return nil
			}
			if _, err := os.Stat(o.BlobPath); err != nil {
				problems = append(problems, fmt.Sprintf("object %s (%s/%s): blob missing", o.ID, o.Tenant, o.Path))
			}
			switch o.State {
			case model.StateReady:
				if o.QueueSeq == 0 || tx.Bucket(bQueue).Get(queueKey(o.Tenant, o.QueueSeq, o.ID)) == nil {
					problems = append(problems, fmt.Sprintf("object %s: READY but not queued", o.ID))
				}
			case model.StateLeased:
				if tx.Bucket(bLeases).Get(timeIDKey(o.LeaseUntil, o.ID)) == nil {
					problems = append(problems, fmt.Sprintf("object %s: LEASED without a lease index entry", o.ID))
				}
			}
			return nil
		})
	})
	return problems, err
}
