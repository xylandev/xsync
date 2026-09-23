package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/store"
)

func TestClaimRangeAndCommit(t *testing.T) {
	root := t.TempDir()
	cap := capacity.New(root, config.Default().Capacity, nil)
	st, err := store.Open(root, cap, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := st.BeginUpload(context.Background(), "tenant", "file.txt", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.WriteAt([]byte("hello world"), 0)
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	key := "secret"
	sum := sha256.Sum256([]byte(key))
	handler := New(st, cap, []config.Tenant{{ID: "tenant", APIKeySHA256: hex.EncodeToString(sum[:])}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	do := func(method, path string, body io.Reader) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	resp := do(http.MethodPost, "/v1/claims", bytes.NewBufferString(`{"client_id":"client","lease_seconds":60}`))
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("claim status=%d %s", resp.StatusCode, raw)
	}
	var claim model.Claim
	_ = json.NewDecoder(resp.Body).Decode(&claim)
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/objects/"+claim.ObjectID+"/content", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Xsync-Lease-ID", claim.LeaseID)
	req.Header.Set("Range", "bytes=6-")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(raw) != "world" {
		t.Fatalf("range status=%d body=%q", resp.StatusCode, raw)
	}
	commit, _ := json.Marshal(map[string]any{"lease_id": claim.LeaseID, "sha256": claim.SHA256, "size": claim.Size})
	resp = do(http.MethodPost, "/v1/objects/"+claim.ObjectID+"/commit", bytes.NewReader(commit))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("commit status=%d", resp.StatusCode)
	}
	resp = do(http.MethodPost, "/v1/objects/"+claim.ObjectID+"/commit", bytes.NewReader(commit))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idempotent commit status=%d", resp.StatusCode)
	}
	if _, err = st.Object(claim.ObjectID); err == nil {
		t.Fatal("committed object remains")
	}
	_ = time.Second
}

// The authenticated tenant must come from the request context, never from a
// header a client can set.
func TestTenantHeaderIsNotTrusted(t *testing.T) {
	root := t.TempDir()
	cap := capacity.New(root, config.Default().Capacity, nil)
	st, err := store.Open(root, cap, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := st.BeginUpload(context.Background(), "victim", "secret.txt", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("confidential"), 0); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}

	key := "attacker-key"
	sum := sha256.Sum256([]byte(key))
	handler := New(st, cap, []config.Tenant{
		{ID: "attacker", APIKeySHA256: hex.EncodeToString(sum[:])},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/claims", bytes.NewBufferString(`{"client_id":"c"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Xsync-Tenant", "victim")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The attacker's own queue is empty, so a spoof-proof server answers 204.
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("spoofed tenant header changed the result: status=%d body=%s", resp.StatusCode, raw)
	}
}
