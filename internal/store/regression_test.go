package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func content(t *testing.T, s *Store, tenant, name string) string {
	t.Helper()
	f, _, err := s.OpenCurrent(tenant, name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertDigest(t *testing.T, s *Store, tenant, name string) {
	t.Helper()
	o, err := s.Current(tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content(t, s, tenant, name)))
	if o.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("catalog digest does not match blob")
	}
}

// Every failure after the client finished writing used to be reported to the
// uploader as success while the object was never published.
func TestFinalizeFailureIsReportedToTheUploader(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// objects/t as a regular file makes MkdirAll fail with ENOTDIR.
	if err := os.WriteFile(filepath.Join(root, "objects", "t"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := s.BeginUpload(context.Background(), "t", "doomed.bin", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err == nil {
		t.Fatal("Close reported success for an upload that was not published")
	}
	if _, err = s.Current("t", "doomed.bin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("object unexpectedly published: %v", err)
	}
}

// FTP APPE and SFTP O_APPEND wrote from offset 0 over the cloned version,
// publishing "BBBAAAAAAA" with a self-consistent digest.
func TestAppendAddsToTheEnd(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "log.txt", "AAAAAAAAAA")

	h, err := s.OpenUpload(context.Background(), "t", "log.txt", "sftp", ModeAppend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("BBB"), 0); err != nil { // relative offsets
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "log.txt"); got != "AAAAAAAAAABBB" {
		t.Fatalf("append produced %q", got)
	}

	h, err = s.OpenUpload(context.Background(), "t", "log.txt", "ftp", ModeAppend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Append([]byte("CC")); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Append([]byte("D")); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "log.txt"); got != "AAAAAAAAAABBBCCD" {
		t.Fatalf("APPE produced %q", got)
	}
	assertDigest(t, s, "t", "log.txt")

	// Absolute offsets starting at the current size are also accepted.
	h, err = s.OpenUpload(context.Background(), "t", "log.txt", "sftp", ModeAppend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("E"), 16); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "log.txt"); got != "AAAAAAAAAABBBCCDE" {
		t.Fatalf("absolute append produced %q", got)
	}
}

// A rejected upload left an interrupted partial that the next non-truncating
// open silently used as its base.
func TestResumeDoesNotAdoptHiddenPartialForAFreshWrite(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "v1-short")
	h, err := s.BeginUpload(context.Background(), "t", "f", "s3")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("v2-short-BAD-DIGEST-CONTENT"), 0)
	h.TransferError(errors.New("connection reset"))
	_ = h.Close()

	r, err := s.BeginUploadFromCurrent(context.Background(), "t", "f", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.WriteAt([]byte("v3-new!!"), 0); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "f"); got != "v3-new!!" {
		t.Fatalf("published %q", got)
	}
}

// Writing past the end of everything that exists used to publish zero-filled
// holes whose digest matched the corrupt content.
func TestResumeAtUnknownOffsetIsRejected(t *testing.T) {
	s := openTest(t)
	h, err := s.BeginUploadFromCurrent(context.Background(), "t", "new.bin", "ftp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("tail"), 6); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err == nil {
		t.Fatal("upload with a hole was published")
	}
	if _, err = s.Current("t", "new.bin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hole-filled object published: %v", err)
	}
}

func TestResumeWithReorderedWritesFillsPrefixFromPartial(t *testing.T) {
	s := openTest(t)
	h, err := s.BeginUpload(context.Background(), "t", "big.bin", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("0123456789"), 0)
	h.TransferError(errors.New("disconnect"))
	_ = h.Close()
	if info, err := s.Stat("t", "big.bin"); err != nil || !info.Partial || info.Size != 10 {
		t.Fatalf("stat = %+v, %v; want partial of 10 bytes", info, err)
	}

	r, err := s.BeginUploadFromCurrent(context.Background(), "t", "big.bin", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	// The second packet arrives first.
	if _, err = r.WriteAt([]byte("EF"), 14); err != nil {
		t.Fatal(err)
	}
	if _, err = r.WriteAt([]byte("ABCD"), 10); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "big.bin"); got != "0123456789ABCDEF" {
		t.Fatalf("resumed content %q", got)
	}
	assertDigest(t, s, "t", "big.bin")
}

func TestInterruptedUploadKeepsOnlyItsContiguousPrefix(t *testing.T) {
	s := openTest(t)
	h, err := s.BeginUpload(context.Background(), "t", "gap.bin", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("AAAA"), 0)
	_, _ = h.WriteAt([]byte("CCCC"), 8) // bytes 4..8 never arrived
	h.TransferError(errors.New("disconnect"))
	_ = h.Close()
	info, err := s.Stat("t", "gap.bin")
	if err != nil || info.Size != 4 {
		t.Fatalf("resume point = %+v, %v; want 4", info, err)
	}
}

func TestTruncateThroughHandle(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "old content that is long")
	h, err := s.BeginUploadFromCurrent(context.Background(), "t", "f", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "f"); got != "new" {
		t.Fatalf("got %q", got)
	}
}

func TestOpenWithoutWritesLeavesContentAlone(t *testing.T) {
	s := openTest(t)
	first := put(t, s, "t", "f", "keep")
	h, err := s.BeginUploadFromCurrent(context.Background(), "t", "f", "sftp")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if o, _ := s.Current("t", "f"); o.ID != first.ID() {
		t.Fatal("a no-op open published a new version")
	}
}

func withPolicy(s *Store, p Policy) { s.SetPolicy(func(string) Policy { return p }) }

// A conflicting object used to go back to the head of the queue forever and
// block every other delivery.
func TestReleasedObjectsGoToTheTailAndPoisonIsParked(t *testing.T) {
	s := openTest(t)
	pol := DefaultPolicy()
	pol.MaxAttempts = 3
	withPolicy(s, pol)
	poison := put(t, s, "t", "poison", "p")
	put(t, s, "t", "good", "g")

	c, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c.ObjectID != poison.ID() {
		t.Fatalf("first claim = %+v, %v", c, err)
	}
	if err = s.ReleaseWith("t", c.LeaseID, ReleaseOptions{Reason: "conflict"}); err != nil {
		t.Fatal(err)
	}
	c2, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c2.Path != "good" {
		t.Fatalf("released object blocked the queue: next claim = %+v, %v", c2, err)
	}
	for i := 0; i < 2; i++ {
		c, err = s.ClaimNext("t", "c", "", time.Minute)
		if err != nil || c.Path != "poison" {
			t.Fatalf("claim %d = %+v, %v", i, c, err)
		}
		if err = s.ReleaseWith("t", c.LeaseID, ReleaseOptions{Reason: "conflict"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("poison object still delivered after max attempts: %v", err)
	}
	parked, err := s.ListParked("t", 10)
	if err != nil || len(parked) != 1 || parked[0].ID != poison.ID() || parked[0].LastError != "conflict" {
		t.Fatalf("parked = %+v, %v", parked, err)
	}
	if err = s.Requeue("t", poison.ID()); err != nil {
		t.Fatal(err)
	}
	c, err = s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c.ObjectID != poison.ID() || c.Attempts != 1 {
		t.Fatalf("requeued claim = %+v, %v", c, err)
	}
	if err = s.ReleaseWith("t", c.LeaseID, ReleaseOptions{Permanent: true, Reason: "cannot write"}); err != nil {
		t.Fatal(err)
	}
	if stats, _ := s.Stats(); stats.Parked != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDelayedRetryIsInvisibleUntilDue(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "x")
	c, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ReleaseWith("t", c.LeaseID, ReleaseOptions{RetryAfter: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delayed object delivered early: %v", err)
	}
	if _, ok := s.NextVisible("t"); !ok {
		t.Fatal("next visible time not reported")
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err = s.ClaimNext("t", "c", "", time.Minute); err != nil {
		t.Fatalf("delayed object not delivered when due: %v", err)
	}
}

func TestUncountedReleaseReturnsTheAttempt(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "x")
	c, _ := s.ClaimNext("t", "c", "", time.Minute)
	if err := s.ReleaseWith("t", c.LeaseID, ReleaseOptions{Uncounted: true}); err != nil {
		t.Fatal(err)
	}
	c, _ = s.ClaimNext("t", "c", "", time.Minute)
	if c.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", c.Attempts)
	}
}

func TestOverwriteSupersedesUndeliveredVersion(t *testing.T) {
	s := openTest(t)
	v1 := put(t, s, "t", "daily.csv", "monday")
	v2 := put(t, s, "t", "daily.csv", "tuesday")
	if _, err := s.Object(v1.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded version still stored: %v", err)
	}
	c, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c.ObjectID != v2.ID() {
		t.Fatalf("claim = %+v, %v", c, err)
	}
	if _, err = s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("superseded version still delivered")
	}
}

func TestOverwriteRetractsLeasedVersion(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "v1")
	c1, _ := s.ClaimNext("t", "c", "", time.Minute)
	put(t, s, "t", "f", "v2")
	// The leased v1 is not delivered again after a failed attempt ...
	if err := s.Release("t", c1.LeaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Object(c1.ObjectID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retracted version survived its release: %v", err)
	}
	c2, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c2.Path != "f" || c2.ObjectID == c1.ObjectID {
		t.Fatalf("claim = %+v, %v", c2, err)
	}
	// ... but a retracted object that was already delivered commits cleanly.
	put(t, s, "t", "g", "v1")
	c3, _ := s.ClaimNext("t", "c", "", time.Minute)
	put(t, s, "t", "g", "v2")
	if _, err := s.Commit("t", c3.ObjectID, c3.LeaseID, c3.SHA256, c3.Size); err != nil {
		t.Fatalf("commit of retracted object: %v", err)
	}
	if got := content(t, s, "t", "g"); got != "v2" {
		t.Fatalf("commit of old version touched the new one: %q", got)
	}
}

func TestKeepPolicyDeliversEveryVersion(t *testing.T) {
	s := openTest(t)
	pol := DefaultPolicy()
	pol.Supersede = false
	withPolicy(s, pol)
	put(t, s, "t", "f", "v1")
	put(t, s, "t", "f", "v2")
	claims, err := s.Claim("t", ClaimOptions{ClientID: "c", Max: 10})
	if err != nil || len(claims) != 2 || claims[0].Version > claims[1].Version {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
}

// Tools that upload to a temporary name and rename it into place must not
// have the temporary name delivered.
func TestHeldTemporaryNameIsDeliveredOnlyAfterRename(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "report.csv.filepart", "data")
	if _, err := s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("temporary name delivered: %v", err)
	}
	if stats, _ := s.Stats(); stats.Held != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	put(t, s, "t", "report.csv", "old")
	// Posix rename over an existing file.
	if err := s.RenameWith("t", "report.csv.filepart", "report.csv", true); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c.Path != "report.csv" {
		t.Fatalf("claim = %+v, %v", c, err)
	}
	if got := content(t, s, "t", "report.csv"); got != "data" {
		t.Fatalf("content = %q", got)
	}
	if _, err := s.ClaimNext("t", "c", "", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("the replaced version was still delivered")
	}
}

func TestRenameOfDeliveringObjectIsRefused(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "a", "x")
	if _, err := s.ClaimNext("t", "c", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("t", "a", "b"); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestRenameKeepsQueuePositionAndUpdatesPath(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "dir/a", "a")
	put(t, s, "t", "b", "b")
	if err := s.Rename("t", "dir", "moved"); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClaimNext("t", "c", "moved", time.Minute)
	if err != nil || c.Path != "moved/a" {
		t.Fatalf("claim = %+v, %v", c, err)
	}
	if problems, _ := s.Check(); len(problems) > 0 {
		t.Fatalf("catalog check: %v", problems)
	}
}

func TestFileAndDirectoryCannotShareAName(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "a", "file")
	if err := s.Mkdir("t", "a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("mkdir over file: %v", err)
	}
	if _, err := s.BeginUpload(context.Background(), "t", "a/b", "test"); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("upload under a file: %v", err)
	}
	put(t, s, "t", "d/x", "x")
	if _, err := s.BeginUpload(context.Background(), "t", "d", "test"); !errors.Is(err, ErrIsDirectory) {
		t.Fatalf("upload over a directory: %v", err)
	}
}

// Maintenance used to delete a partial that had just been resumed.
func TestReclaimSkipsUploadResumedSinceTheScan(t *testing.T) {
	s := openTest(t)
	h, _ := s.BeginUpload(context.Background(), "t", "f", "sftp")
	_, _ = h.WriteAt([]byte("abc"), 0)
	h.TransferError(errors.New("x"))
	_ = h.Close()
	r, _ := s.BeginUploadFromCurrent(context.Background(), "t", "f", "sftp")
	if _, err := r.WriteAt([]byte("def"), 3); err != nil {
		t.Fatal(err)
	}
	// The scan would have seen the old INTERRUPTED record.
	if err := s.reclaimUpload(r.ID(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("resumed upload was destroyed by maintenance: %v", err)
	}
	if got := content(t, s, "t", "f"); got != "abcdef" {
		t.Fatalf("content = %q", got)
	}
}

func TestLeaseExpiryRequeuesThroughIndex(t *testing.T) {
	s := openTest(t)
	put(t, s, "t", "f", "x")
	c, _ := s.ClaimNext("t", "c", "", time.Second)
	s.now = func() time.Time { return time.Now().Add(time.Minute) }
	if err := s.ExpireLeases(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Renew("t", c.LeaseID, time.Minute); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("expired lease renewed: %v", err)
	}
	c2, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c2.ObjectID != c.ObjectID || c2.Attempts != 2 {
		t.Fatalf("claim after expiry = %+v, %v", c2, err)
	}
	if _, err = s.Commit("t", c.ObjectID, c.LeaseID, c.SHA256, c.Size); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("stale lease committed: %v", err)
	}
	stats, _ := s.Stats()
	want, _ := s.scanStats()
	if stats != want {
		t.Fatalf("counters %+v != scan %+v", stats, want)
	}
}

func TestBatchClaimAndPrefixIndex(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 5; i++ {
		put(t, s, "t", fmt.Sprintf("in/%d", i), "x")
		put(t, s, "t", fmt.Sprintf("other/%d", i), "y")
	}
	claims, err := s.Claim("t", ClaimOptions{ClientID: "c", Prefix: "in", Max: 3})
	if err != nil || len(claims) != 3 {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	for i, c := range claims {
		if c.Path != fmt.Sprintf("in/%d", i) {
			t.Fatalf("claim %d path %s, want queue order", i, c.Path)
		}
	}
	rest, err := s.Claim("t", ClaimOptions{ClientID: "c", Max: 100})
	if err != nil || len(rest) != 7 {
		t.Fatalf("remaining claims = %d, %v", len(rest), err)
	}
}

func TestQuotaRejectsUploads(t *testing.T) {
	s := openTest(t)
	pol := DefaultPolicy()
	pol.MaxStoredBytes = 5
	withPolicy(s, pol)
	put(t, s, "t", "a", "123456")
	if _, err := s.BeginUpload(context.Background(), "t", "b", "test"); !errors.Is(err, ErrQuota) {
		t.Fatalf("err = %v, want quota", err)
	}
	if _, err := s.BeginUpload(context.Background(), "other", "b", "test"); err != nil {
		t.Fatalf("quota leaked across tenants: %v", err)
	}
}

func TestDrainBlocksNewUploads(t *testing.T) {
	s := openTest(t)
	h, _ := s.BeginUpload(context.Background(), "t", "a", "test")
	s.Drain()
	if _, err := s.BeginUpload(context.Background(), "t", "b", "test"); !errors.Is(err, ErrDraining) {
		t.Fatalf("err = %v", err)
	}
	_, _ = h.WriteAt([]byte("x"), 0)
	if err := h.Close(); err != nil {
		t.Fatalf("in-flight upload broken by drain: %v", err)
	}
	if err := s.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListKeysPagesWithDelimiter(t *testing.T) {
	s := openTest(t)
	for _, k := range []string{"a/1", "a/2", "b", "c/x/1", "d"} {
		put(t, s, "t", k, "x")
	}
	var got []string
	after := ""
	for {
		page, err := s.ListKeys("t", "", "/", after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page.Objects {
			got = append(got, o.Path)
		}
		got = append(got, page.CommonPrefixes...)
		if !page.Truncated {
			break
		}
		after = page.NextAfter
	}
	want := "a/,b,c/,d"
	joined := strings.Join(sortStrings(got), ",")
	if joined != want {
		t.Fatalf("listing = %s, want %s", joined, want)
	}
	page, _ := s.ListKeys("t", "a/", "", "", 10)
	if len(page.Objects) != 2 {
		t.Fatalf("prefix listing = %+v", page)
	}
}

func sortStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// A catalog written by the first release must open, keep its queue order and
// finish its two-phase deletes.
func TestMigratesSchemaOneCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "metadata"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "objects", "t"), 0o750); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(root, "metadata", "catalog.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(id, p string, version uint64, state model.State) model.ObjectVersion {
		blob := filepath.Join(root, "objects", "t", id+".blob")
		if err := os.WriteFile(blob, []byte(p), 0o640); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(p))
		return model.ObjectVersion{ID: id, Tenant: "t", Path: p, BlobPath: blob, Size: int64(len(p)), SHA256: hex.EncodeToString(sum[:]), Version: version, State: state, QueueKey: fmt.Sprintf("t\x00%020d\x00%s", now.UnixNano(), id), CreatedAt: now, UpdatedAt: now}
	}
	objs := []model.ObjectVersion{
		mk("bbbb", "second", 2, model.StateReady),
		mk("aaaa", "first", 1, model.StateReady),
		mk("cccc", "deleting", 3, model.StateDeletePending),
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"objects", "namespace", "queue", "claims", "uploads", "tombstones", "versions", "directories"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		for _, o := range objs {
			if err := putJSON(tx.Bucket([]byte("objects")), []byte(o.ID), o); err != nil {
				return err
			}
			if err := tx.Bucket([]byte("namespace")).Put(nsKey("t", o.Path), []byte(o.ID)); err != nil {
				return err
			}
			if o.State == model.StateReady {
				if err := tx.Bucket([]byte("queue")).Put([]byte(o.QueueKey), []byte(o.ID)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.ClaimNext("t", "c", "", time.Minute)
	if err != nil || c.ObjectID != "aaaa" {
		t.Fatalf("first claim after migration = %+v, %v", c, err)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", "t", "cccc.blob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy DELETE_PENDING blob not collected")
	}
	if _, err := s.Current("t", "deleting"); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy DELETE_PENDING object still published")
	}
	if problems, _ := s.Check(); len(problems) != 0 {
		t.Fatalf("check after migration: %v", problems)
	}
	stats, _ := s.Stats()
	want, _ := s.scanStats()
	if stats != want {
		t.Fatalf("counters %+v != scan %+v", stats, want)
	}
}

func TestReconcileRemovesOrphans(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	keep := put(t, s, "t", "keep", "k")
	orphan := filepath.Join(root, "objects", "t", "ffffffffffffffffffffffffffffffff.blob")
	if err := os.WriteFile(orphan, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(orphan, old, old)
	if err := s.Reconcile(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan blob not removed")
	}
	if _, err := s.Object(keep.ID()); err != nil {
		t.Fatal(err)
	}
	if got := content(t, s, "t", "keep"); got != "k" {
		t.Fatal("reconcile touched a live blob")
	}
}

// Out-of-order SFTP writes should not force a full reread.
func TestStreamHasherAbsorbsReordering(t *testing.T) {
	h := newStreamHasher()
	data := []byte("abcdefghij")
	h.write(data[4:8], 4)
	h.write(data[8:], 8)
	h.write(data[:4], 0)
	got := h.result(10)
	sum := sha256.Sum256(data)
	if got == nil || got.digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("reordered digest = %+v", got)
	}
	h2 := newStreamHasher()
	h2.write(data, 0)
	h2.write(data[:2], 0)
	if h2.result(10) != nil {
		t.Fatal("rewrite of hashed bytes not detected")
	}
}
