package store

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
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
	s, err := Open(t.TempDir(), nil)
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

func TestRenameDirectoryRejectsDestinationSubtree(t *testing.T) {
	s, err := Open(t.TempDir(), nil)
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
	s, err := Open(t.TempDir(), nil)
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
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.BeginUploadFromCurrent(context.Background(), "t", "file", "test")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ID() != h.ID() {
		t.Fatalf("created new upload %s, wanted resume %s", resumed.ID(), h.ID())
	}
	_, _ = resumed.WriteAt([]byte(" world"), 5)
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
