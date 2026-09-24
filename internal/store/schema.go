package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

// SchemaVersion is the catalog layout this code reads and writes. Opening an
// older catalog rebuilds every index from the primary records.
const SchemaVersion = 2

// Primary buckets hold facts; index buckets can always be rebuilt from them.
var (
	bMeta        = []byte("meta")
	bObjects     = []byte("objects")     // id -> ObjectVersion
	bNamespace   = []byte("namespace")   // tenant\0path -> id
	bUploads     = []byte("uploads")     // id -> Upload
	bClaims      = []byte("claims")      // lease -> Claim
	bTombstones  = []byte("tombstones")  // id -> Tombstone
	bGC          = []byte("gc")          // id -> gcEntry (blob still to unlink)
	bVersions    = []byte("versions")    // sequence only
	bDirectories = []byte("directories") // tenant\0path -> Entry

	bQueue       = []byte("queue")        // tenant\0seq\0id -> visible\0path
	bQueueSeg    = []byte("queue_seg")    // tenant\0firstseg\0seq\0id -> visible\0path
	bLeases      = []byte("lease_expiry") // expiry\0id -> lease
	bUploadPaths = []byte("upload_paths") // tenant\0path\0id -> ""
	bStale       = []byte("stale")        // updated\0id -> "" (INTERRUPTED/FAILED uploads)
	bHeld        = []byte("held")         // created\0id -> ""
	bParked      = []byte("parked")       // tenant\0parked\0id -> ""
	bTombTimes   = []byte("tomb_times")   // deleted\0id -> ""
)

var primaryBuckets = [][]byte{bMeta, bObjects, bNamespace, bUploads, bClaims, bTombstones, bGC, bVersions, bDirectories}
var indexBuckets = [][]byte{bQueue, bQueueSeg, bLeases, bUploadPaths, bStale, bHeld, bParked, bTombTimes}

type gcEntry struct {
	Tenant string `json:"tenant"`
	Blob   string `json:"blob"`
	Size   int64  `json:"size"`
}

func u64key(n uint64) string { return fmt.Sprintf("%020d", n) }

func tskey(t time.Time) string {
	n := t.UnixNano()
	if n < 0 {
		n = 0
	}
	return u64key(uint64(n))
}

func parseTS(s string) time.Time {
	n, _ := strconv.ParseInt(s, 10, 64)
	return time.Unix(0, n).UTC()
}

func nsKey(tenant, name string) []byte { return []byte(tenant + "\x00" + name) }

func firstSegment(p string) string {
	seg, _, _ := strings.Cut(p, "/")
	return seg
}

func queueKey(tenant string, seq uint64, id string) []byte {
	return []byte(tenant + "\x00" + u64key(seq) + "\x00" + id)
}

func queueSegKey(tenant, p string, seq uint64, id string) []byte {
	return []byte(tenant + "\x00" + firstSegment(p) + "\x00" + u64key(seq) + "\x00" + id)
}

func queueValue(visible time.Time, p string) []byte {
	return []byte(tskey(visible) + "\x00" + p)
}

func parseQueueValue(v []byte) (time.Time, string) {
	ts, p, _ := bytes.Cut(v, []byte{0})
	return parseTS(string(ts)), string(p)
}

// parseTailKey splits "...\0seq\0id" and returns seq and id.
func parseTailKey(k []byte) (uint64, string) {
	i := bytes.LastIndexByte(k, 0)
	if i < 0 {
		return 0, ""
	}
	id := string(k[i+1:])
	j := bytes.LastIndexByte(k[:i], 0)
	seq, _ := strconv.ParseUint(string(k[j+1:i]), 10, 64)
	return seq, id
}

func timeIDKey(t time.Time, id string) []byte { return []byte(tskey(t) + "\x00" + id) }

func parseTimeIDKey(k []byte) (time.Time, string) {
	ts, id, _ := bytes.Cut(k, []byte{0})
	return parseTS(string(ts)), string(id)
}

func uploadPathKey(tenant, p, id string) []byte {
	return []byte(tenant + "\x00" + p + "\x00" + id)
}

func parkedKey(tenant string, at time.Time, id string) []byte {
	return []byte(tenant + "\x00" + tskey(at) + "\x00" + id)
}

// enqueue appends o to the tail of its tenant's delivery queue.
func enqueue(tx *bolt.Tx, o *model.ObjectVersion, visible time.Time) error {
	seq, err := tx.Bucket(bQueue).NextSequence()
	if err != nil {
		return err
	}
	o.QueueSeq, o.VisibleAt = seq, visible
	return putQueueEntries(tx, o)
}

func putQueueEntries(tx *bolt.Tx, o *model.ObjectVersion) error {
	v := queueValue(o.VisibleAt, o.Path)
	if err := tx.Bucket(bQueue).Put(queueKey(o.Tenant, o.QueueSeq, o.ID), v); err != nil {
		return err
	}
	return tx.Bucket(bQueueSeg).Put(queueSegKey(o.Tenant, o.Path, o.QueueSeq, o.ID), v)
}

// dequeue removes o's queue entries. It must run before o.Path changes.
func dequeue(tx *bolt.Tx, o *model.ObjectVersion) error {
	if o.QueueSeq == 0 {
		return nil
	}
	if err := tx.Bucket(bQueue).Delete(queueKey(o.Tenant, o.QueueSeq, o.ID)); err != nil {
		return err
	}
	if err := tx.Bucket(bQueueSeg).Delete(queueSegKey(o.Tenant, o.Path, o.QueueSeq, o.ID)); err != nil {
		return err
	}
	o.QueueSeq = 0
	return nil
}

func (s *Store) schemaVersion(tx *bolt.Tx) int {
	raw := tx.Bucket(bMeta).Get([]byte("schema"))
	n, _ := strconv.Atoi(string(raw))
	return n
}

// migrate creates missing buckets and rebuilds indexes when the catalog was
// written by an older layout.
func (s *Store) migrate() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range append(append([][]byte{}, primaryBuckets...), indexBuckets...) {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		// The pre-schema-2 queue used different keys; drop it before the
		// rebuild creates fresh buckets.
		version := s.schemaVersion(tx)
		if version == SchemaVersion {
			return nil
		}
		if version > SchemaVersion {
			return fmt.Errorf("catalog schema %d is newer than this server supports (%d)", version, SchemaVersion)
		}
		s.log.Info("migrating catalog", "from_schema", version, "to_schema", SchemaVersion)
		if err := s.rebuildIndexes(tx); err != nil {
			return err
		}
		return tx.Bucket(bMeta).Put([]byte("schema"), []byte(strconv.Itoa(SchemaVersion)))
	})
}

// RebuildIndexes recreates every index bucket from the primary records. It is
// the migration path and the repair tool for a damaged index.
func (s *Store) RebuildIndexes() error {
	if err := s.db.Update(s.rebuildIndexes); err != nil {
		return err
	}
	return s.recount()
}

func (s *Store) rebuildIndexes(tx *bolt.Tx) error {
	for _, b := range indexBuckets {
		if tx.Bucket(b) != nil {
			if err := tx.DeleteBucket(b); err != nil {
				return err
			}
		}
		if _, err := tx.CreateBucket(b); err != nil {
			return err
		}
	}
	now := s.now().UTC()
	objects := tx.Bucket(bObjects)
	var all []model.ObjectVersion
	if err := objects.ForEach(func(_, v []byte) error {
		var o model.ObjectVersion
		if json.Unmarshal(v, &o) == nil {
			all = append(all, o)
		}
		return nil
	}); err != nil {
		return err
	}
	// Rebuild the queue in version order, which is publish order.
	sortObjectsByVersion(all)
	for i := range all {
		o := all[i]
		changed := false
		switch o.State {
		case model.StateReady:
			o.QueueKey = ""
			if err := enqueue(tx, &o, o.VisibleAt); err != nil {
				return err
			}
			changed = true
		case model.StateLeased:
			o.QueueSeq, o.QueueKey = 0, ""
			if err := tx.Bucket(bLeases).Put(timeIDKey(o.LeaseUntil, o.ID), []byte(o.LeaseID)); err != nil {
				return err
			}
			changed = true
		case model.StateHeld:
			if err := tx.Bucket(bHeld).Put(timeIDKey(o.CreatedAt, o.ID), nil); err != nil {
				return err
			}
		case model.StateParked:
			if err := tx.Bucket(bParked).Put(parkedKey(o.Tenant, o.ParkedAt, o.ID), nil); err != nil {
				return err
			}
		case model.StateDeletePending:
			// Legacy two-phase delete: the decision is durable, finish it
			// through the garbage collector.
			if err := s.deleteObjectTx(tx, &delta{}, o, "committed"); err != nil {
				return err
			}
			continue
		}
		if changed {
			if err := putJSON(objects, []byte(o.ID), o); err != nil {
				return err
			}
		}
	}
	uploads := tx.Bucket(bUploads)
	if err := uploads.ForEach(func(_, v []byte) error {
		var u model.Upload
		if json.Unmarshal(v, &u) != nil {
			return nil
		}
		if err := tx.Bucket(bUploadPaths).Put(uploadPathKey(u.Tenant, u.Path, u.ID), nil); err != nil {
			return err
		}
		if u.State == model.StateInterrupted || u.State == model.StateFailed {
			return tx.Bucket(bStale).Put(timeIDKey(u.UpdatedAt, u.ID), nil)
		}
		return nil
	}); err != nil {
		return err
	}
	// Claims whose objects are no longer leased are stale.
	claims := tx.Bucket(bClaims)
	var staleClaims [][]byte
	if err := claims.ForEach(func(k, v []byte) error {
		var c model.Claim
		if json.Unmarshal(v, &c) != nil {
			staleClaims = append(staleClaims, bytes.Clone(k))
			return nil
		}
		o, err := getJSON[model.ObjectVersion](objects, []byte(c.ObjectID))
		if err != nil || o.State != model.StateLeased || o.LeaseID != string(k) {
			staleClaims = append(staleClaims, bytes.Clone(k))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range staleClaims {
		if err := claims.Delete(k); err != nil {
			return err
		}
	}
	return tx.Bucket(bTombstones).ForEach(func(k, v []byte) error {
		var t model.Tombstone
		if json.Unmarshal(v, &t) != nil {
			t.DeletedAt = now
		}
		return tx.Bucket(bTombTimes).Put(timeIDKey(t.DeletedAt, string(k)), nil)
	})
}

func sortObjectsByVersion(all []model.ObjectVersion) {
	sort.Slice(all, func(i, j int) bool {
		if all[i].Version != all[j].Version {
			return all[i].Version < all[j].Version
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
}

// recount rebuilds the in-memory counters from one scan of the catalog.
func (s *Store) recount() error {
	var stats Stats
	tenants := map[string]TenantStats{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bObjects).ForEach(func(_, v []byte) error {
			var o model.ObjectVersion
			if json.Unmarshal(v, &o) != nil {
				return nil
			}
			t := tenants[o.Tenant]
			t.Objects++
			t.Bytes += o.Size
			bump(&t, o.State, 1)
			tenants[o.Tenant] = t
			return nil
		}); err != nil {
			return err
		}
		stats.Uploads = tx.Bucket(bUploads).Stats().KeyN
		stats.Claims = tx.Bucket(bClaims).Stats().KeyN
		stats.DeletePending = tx.Bucket(bGC).Stats().KeyN
		return nil
	})
	if err != nil {
		return err
	}
	for _, t := range tenants {
		stats.Objects += t.Objects
		stats.Ready += t.Ready
		stats.Leased += t.Leased
		stats.Held += t.Held
		stats.Parked += t.Parked
		stats.Bytes += t.Bytes
	}
	s.count.set(stats, tenants)
	return nil
}
