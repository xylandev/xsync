package store

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/model"
	bolt "go.etcd.io/bbolt"
)

func put(t *testing.T, s *Store, tenant, name, body string) *UploadHandle {
	t.Helper()
	h, err := s.BeginUpload(context.Background(), tenant, name, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte(body), 0); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVersionSnapshotAndConditionalDelete(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := put(t, s, "tenant", "dir/file.txt", "first")
	claim, err := s.ClaimNext("tenant", "client", "dir", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claim.ObjectID != first.ID() {
		t.Fatalf("claimed %s want %s", claim.ObjectID, first.ID())
	}
	f, _, err := s.OpenClaim("tenant", claim.ObjectID, claim.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(raw) != "first" {
		t.Fatalf("snapshot=%q err=%v", raw, err)
	}
	second := put(t, s, "tenant", "dir/file.txt", "second")
	deleted, err := s.Commit("tenant", claim.ObjectID, claim.LeaseID, claim.SHA256, claim.Size)
	if err != nil || !deleted {
		t.Fatal(err)
	}
	current, err := s.Current("tenant", "dir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != second.ID() {
		t.Fatalf("conditional delete removed replacement: got %s want %s", current.ID, second.ID())
	}
	if _, err = s.Object(first.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old object still present: %v", err)
	}
	deleted, err = s.Commit("tenant", claim.ObjectID, claim.LeaseID, claim.SHA256, claim.Size)
	if err != nil {
		t.Fatalf("idempotent commit failed: %v", err)
	}
	if deleted {
		t.Fatal("idempotent commit reported a second deletion")
	}
}

// A torn crash plus an unreadable blob must not keep the service from starting.
func TestRecoverParksUnrecoverableUploadAndStillOpens(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lost := model.Upload{
		ID: "0123456789abcdef", Tenant: "t", Path: "lost.bin", Protocol: "test",
		StagingPath: filepath.Join(root, "staging", "t", "0123456789abcdef.partial"),
		State:       model.StateFinalizing, CreatedAt: now, UpdatedAt: now,
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bUploads), []byte(lost.ID), lost)
	}); err != nil {
		t.Fatal(err)
	}
	healthy := put(t, s, "t", "healthy.bin", "payload")
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(root, nil, nil)
	if err != nil {
		t.Fatalf("store refused to open because one upload was unrecoverable: %v", err)
	}
	defer s2.Close()

	var got model.Upload
	if err = s2.db.View(func(tx *bolt.Tx) error {
		var e error
		got, e = getJSON[model.Upload](tx.Bucket(bUploads), []byte(lost.ID))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if got.State != model.StateFailed {
		t.Fatalf("unrecoverable upload state = %q, want %q", got.State, model.StateFailed)
	}
	if got.Error == "" {
		t.Fatal("failed upload recorded no cause")
	}
	if _, err = s2.Object(healthy.ID()); err != nil {
		t.Fatalf("healthy object lost during recovery: %v", err)
	}

	// partial_ttl expiry must reclaim FAILED records, not just INTERRUPTED ones.
	s2.now = func() time.Time { return time.Now().UTC().Add(48 * time.Hour) }
	if err = s2.maintenancePass(context.Background(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	err = s2.db.View(func(tx *bolt.Tx) error {
		_, e := getJSON[model.Upload](tx.Bucket(bUploads), []byte(lost.ID))
		return e
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed upload was not reclaimed: %v", err)
	}
}

func TestRenameDirectoryRejectsDestinationSubtree(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source := put(t, s, "tenant", "a/file", "source")
	target := put(t, s, "tenant", "b/file", "target")

	if err = s.Rename("tenant", "a", "b"); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename error = %v, want conflict", err)
	}
	gotSource, err := s.Current("tenant", "a/file")
	if err != nil || gotSource.ID != source.ID() {
		t.Fatalf("source changed after rejected rename: object=%+v err=%v", gotSource, err)
	}
	gotTarget, err := s.Current("tenant", "b/file")
	if err != nil || gotTarget.ID != target.ID() {
		t.Fatalf("target changed after rejected rename: object=%+v err=%v", gotTarget, err)
	}
}

func TestInterruptedUploadCanResume(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, err := s.BeginUpload(context.Background(), "t", "file", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("hello"), 0)
	h.TransferError(errors.New("disconnect"))
	if err = h.Close(); err == nil {
		t.Fatal("interrupted upload reported success")
	}
	resumed, err := s.BeginUploadFromCurrent(context.Background(), "t", "file", "test")
	if err != nil {
		t.Fatal(err)
	}
	// The base is chosen by the first write: offset 5 continues the partial.
	_, _ = resumed.WriteAt([]byte(" world"), 5)
	if resumed.ID() != h.ID() {
		t.Fatalf("created new upload %s, wanted resume %s", resumed.ID(), h.ID())
	}
	if err = resumed.Close(); err != nil {
		t.Fatal(err)
	}
	f, _, err := s.OpenCurrent("t", "file")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(f)
	f.Close()
	if string(raw) != "hello world" {
		t.Fatalf("got %q", raw)
	}
}
