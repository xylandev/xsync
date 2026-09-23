package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

// scanStats recomputes the state distribution the slow way, so tests can assert
// that the in-memory counters Stats reports never drift from the catalog.
func (s *Store) scanStats() (Stats, error) {
	var out Stats
	err := s.db.View(func(tx *bolt.Tx) error {
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
		uc := tx.Bucket(bUploads).Cursor()
		for k, _ := uc.First(); k != nil; k, _ = uc.Next() {
			out.Uploads++
		}
		cc := tx.Bucket(bClaims).Cursor()
		for k, _ := cc.First(); k != nil; k, _ = cc.Next() {
			out.Claims++
		}
		return nil
	})
	return out, err
}

func (s *Store) queueLen(tenant string) int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bQueue).Cursor()
		seek := []byte(tenant + "\x00")
		for k, _ := c.Seek(seek); k != nil && hasBytePrefix(k, seek); k, _ = c.Next() {
			n++
		}
		return nil
	})
	return n
}

func hasBytePrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

func TestStatsCountersTrackCatalogThroughEveryTransition(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		t.Helper()
		want, scanErr := s.scanStats()
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		got, _ := s.Stats()
		if got != want {
			t.Fatalf("%s: counters=%+v, catalog scan=%+v", stage, got, want)
		}
	}
	check("empty")

	put(t, s, "t", "a.bin", "aaa")
	put(t, s, "t", "dir/b.bin", "bbbb")
	check("after publish")

	h, err := s.BeginUpload(context.Background(), "t", "partial.bin", "test")
	if err != nil {
		t.Fatal(err)
	}
	check("upload in flight")
	if _, err = h.WriteAt([]byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	h.TransferError(errors.New("disconnect"))
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	check("after interrupt")

	claim, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	check("after claim")

	if _, err = s.Renew("t", claim.LeaseID, time.Minute); err != nil {
		t.Fatal(err)
	}
	check("after renew")

	if err = s.Release("t", claim.LeaseID); err != nil {
		t.Fatal(err)
	}
	check("after release")

	claim, err = s.ClaimNext("t", "c", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Commit("t", claim.ObjectID, claim.LeaseID, claim.SHA256, claim.Size); err != nil {
		t.Fatal(err)
	}
	check("after commit")

	if err = s.Remove("t", "dir/b.bin"); err != nil {
		t.Fatal(err)
	}
	check("after remove")

	// Expire a lease through the maintenance loop.
	put(t, s, "t", "c.bin", "cc")
	if _, err = s.ClaimNext("t", "c", "", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	if err = s.maintenancePass(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	check("after lease expiry")
	s.now = time.Now

	// Reopening must rebuild the counters from the catalog.
	want, err := s.scanStats()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, _ := s2.Stats(); got != want {
		t.Fatalf("counters after reopen = %+v, want %+v", got, want)
	}
	rescan, err := s2.scanStats()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Stats(); got != rescan {
		t.Fatalf("counters=%+v, catalog scan=%+v", got, rescan)
	}
}

// Leaving leased objects in the queue made draining it quadratic: every claim
// had to walk past every outstanding lease.
func TestClaimDequeuesAndReleaseRequeues(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put(t, s, "t", "a.bin", "a")
	put(t, s, "t", "b.bin", "b")
	if n := s.queueLen("t"); n != 2 {
		t.Fatalf("queue length = %d, want 2", n)
	}

	first, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.queueLen("t"); n != 1 {
		t.Fatalf("leased object still queued: length = %d, want 1", n)
	}
	if _, err = s.ClaimNext("t", "c", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := s.queueLen("t"); n != 0 {
		t.Fatalf("queue length = %d, want 0", n)
	}
	if _, err = s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	if err = s.Release("t", first.LeaseID); err != nil {
		t.Fatal(err)
	}
	if n := s.queueLen("t"); n != 1 {
		t.Fatalf("released object not requeued: length = %d, want 1", n)
	}
	again, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if again.ObjectID != first.ObjectID {
		t.Fatalf("requeued %s, want %s", again.ObjectID, first.ObjectID)
	}
}

// Concurrent uploads exercise the batched commit path and the shared counters.
func TestConcurrentUploadsAndClaimsStayConsistent(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const workers, perWorker = 8, 5
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				h, e := s.BeginUpload(context.Background(), "t", fmt.Sprintf("w%d/f%d", w, i), "test")
				if e != nil {
					t.Error(e)
					return
				}
				if _, e = h.WriteAt([]byte("payload"), 0); e != nil {
					t.Error(e)
					return
				}
				if e = h.Close(); e != nil {
					t.Error(e)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	want, err := s.scanStats()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Stats(); got != want {
		t.Fatalf("counters=%+v, catalog scan=%+v", got, want)
	}
	if want.Objects != workers*perWorker {
		t.Fatalf("published %d objects, want %d", want.Objects, workers*perWorker)
	}

	// Dequeuing inside the write transaction is what keeps two clients from
	// claiming the same object.
	var mu sync.Mutex
	seen := make(map[string]bool, workers*perWorker)
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				claim, e := s.ClaimNext("t", fmt.Sprintf("c%d", w), "", time.Minute)
				if e != nil {
					return
				}
				mu.Lock()
				if seen[claim.ObjectID] {
					t.Errorf("object %s was claimed twice", claim.ObjectID)
				}
				seen[claim.ObjectID] = true
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	if len(seen) != workers*perWorker {
		t.Fatalf("claimed %d distinct objects, want %d", len(seen), workers*perWorker)
	}
	if s.queueLen("t") != 0 {
		t.Fatalf("queue still holds %d leased objects", s.queueLen("t"))
	}
	if want, err = s.scanStats(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Stats(); got != want {
		t.Fatalf("after claims: counters=%+v, catalog scan=%+v", got, want)
	}
}

func TestClaimPrefixMatchesWholePathSegments(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// "database.txt" is queued first and would be matched by a bare string prefix.
	put(t, s, "t", "database.txt", "decoy")
	put(t, s, "t", "data/real.txt", "wanted")

	claim, err := s.ClaimNext("t", "c", "data", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Path != "data/real.txt" {
		t.Fatalf("claimed %q, want data/real.txt", claim.Path)
	}
}
