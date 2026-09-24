package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

type harness struct {
	t   *testing.T
	st  *store.Store
	srv *httptest.Server
	key string
}

func digest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func newHarness(t *testing.T, opts Options, tenants ...config.Tenant) *harness {
	t.Helper()
	root := t.TempDir()
	cap := capacity.New(root, config.Default().Capacity, nil)
	st, err := store.Open(root, cap, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if len(tenants) == 0 {
		tenants = []config.Tenant{{ID: "tenant", APIKeySHA256: digest("secret")}}
	}
	if opts.MaxLongPoll == 0 {
		opts.MaxLongPoll = 5 * time.Second
	}
	srv := httptest.NewServer(New(st, cap, tenant.NewRegistry(tenants), opts, nil))
	t.Cleanup(srv.Close)
	return &harness{t: t, st: st, srv: srv, key: "secret"}
}

func (h *harness) put(tenantID, name, body string) {
	h.t.Helper()
	u, err := h.st.BeginUpload(context.Background(), tenantID, name, "test")
	if err != nil {
		h.t.Fatal(err)
	}
	_, _ = u.WriteAt([]byte(body), 0)
	if err = u.Close(); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) do(method, path, body string, headers ...string) *http.Response {
	h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+h.key)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestClaimRangeAndCommit(t *testing.T) {
	h := newHarness(t, Options{})
	h.put("tenant", "file.txt", "hello world")
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"client","lease_seconds":60}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("claim status=%d %s", resp.StatusCode, raw)
	}
	claim := decode[model.Claim](t, resp)
	resp = h.do(http.MethodGet, "/v1/objects/"+claim.ObjectID+"/content", "", "X-Xsync-Lease-ID", claim.LeaseID, "Range", "bytes=6-")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(raw) != "world" {
		t.Fatalf("range status=%d body=%q", resp.StatusCode, raw)
	}
	commit, _ := json.Marshal(map[string]any{"lease_id": claim.LeaseID, "sha256": claim.SHA256, "size": claim.Size})
	for i := 0; i < 2; i++ {
		resp = h.do(http.MethodPost, "/v1/objects/"+claim.ObjectID+"/commit", string(commit))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("commit %d status=%d", i, resp.StatusCode)
		}
	}
	if _, err := h.st.Object(claim.ObjectID); err == nil {
		t.Fatal("committed object remains")
	}
}

// The authenticated tenant must come from the request context, never from a
// header a client can set.
func TestTenantHeaderIsNotTrusted(t *testing.T) {
	h := newHarness(t, Options{}, config.Tenant{ID: "attacker", APIKeySHA256: digest("secret")})
	h.put("victim", "secret.txt", "confidential")
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`, "X-Xsync-Tenant", "victim")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("spoofed tenant header changed the result: status=%d", resp.StatusCode)
	}
}

func TestBatchClaim(t *testing.T) {
	h := newHarness(t, Options{MaxBatch: 3})
	for _, n := range []string{"a", "b", "c", "d"} {
		h.put("tenant", n, n)
	}
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c","max":10}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body := decode[struct{ Claims []model.Claim }](t, resp)
	if len(body.Claims) != 3 || body.Claims[0].Path != "a" {
		t.Fatalf("claims = %+v", body.Claims)
	}
}

func TestLongPollWakesOnPublish(t *testing.T) {
	h := newHarness(t, Options{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		h.put("tenant", "late.txt", "x")
	}()
	start := time.Now()
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c","max":1,"wait_seconds":5}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body := decode[struct{ Claims []model.Claim }](t, resp)
	if len(body.Claims) != 1 || time.Since(start) > 3*time.Second {
		t.Fatalf("long poll result %+v after %v", body.Claims, time.Since(start))
	}
	resp = h.do(http.MethodPost, "/v1/claims", `{"client_id":"c","wait_seconds":1}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty long poll status=%d", resp.StatusCode)
	}
}

func TestPermanentReleaseParksAndDownloaderCanRequeue(t *testing.T) {
	h := newHarness(t, Options{})
	h.put("tenant", "f", "x")
	claim := decode[model.Claim](t, h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`))
	resp := h.do(http.MethodPost, "/v1/claims/"+claim.LeaseID+"/release", `{"reason":"destination conflict","permanent":true}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release status=%d", resp.StatusCode)
	}
	parked := decode[struct{ Objects []objectView }](t, h.do(http.MethodGet, "/v1/parked", ""))
	if len(parked.Objects) != 1 || parked.Objects[0].LastError != "destination conflict" {
		t.Fatalf("parked = %+v", parked)
	}
	resp = h.do(http.MethodPost, "/v1/objects/"+claim.ObjectID+"/requeue", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("requeue status=%d", resp.StatusCode)
	}
	claim = decode[model.Claim](t, h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`))
	resp = h.do(http.MethodDelete, "/v1/claims/"+claim.LeaseID, `{"permanent":true}`)
	resp.Body.Close()
	resp = h.do(http.MethodDelete, "/v1/objects/"+claim.ObjectID, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete parked status=%d", resp.StatusCode)
	}
	if _, err := h.st.Object(claim.ObjectID); err == nil {
		t.Fatal("dropped object still stored")
	}
}

func TestRenewWithoutBodyKeepsLeaseLength(t *testing.T) {
	h := newHarness(t, Options{})
	h.put("tenant", "f", "x")
	claim := decode[model.Claim](t, h.do(http.MethodPost, "/v1/claims", `{"client_id":"c","lease_seconds":600}`))
	renewed := decode[model.Claim](t, h.do(http.MethodPost, "/v1/claims/"+claim.LeaseID+"/renew", ""))
	if renewed.LeaseUntil.Before(claim.LeaseUntil) {
		t.Fatalf("empty renew shortened the lease: %v -> %v", claim.LeaseUntil, renewed.LeaseUntil)
	}
}

func TestErrorsCarryCodesButNoInternals(t *testing.T) {
	h := newHarness(t, Options{})
	resp := h.do(http.MethodPost, "/v1/objects/nope/commit", `{"lease_id":"x","sha256":"y","size":1}`)
	body := decode[map[string]any](t, resp)
	if resp.StatusCode != http.StatusNotFound || body["code"] != "not_found" {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
	resp = h.do(http.MethodPost, "/v1/claims", `{"client_id":"c","prefix":"../x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid prefix status=%d", resp.StatusCode)
	}
}

func TestAuthFailuresAreThrottled(t *testing.T) {
	h := newHarness(t, Options{Auth: netguard.NewAuthLimiter(3)})
	h.key = "wrong"
	for i := 0; i < 3; i++ {
		resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d", i, resp.StatusCode)
		}
	}
	h.key = "secret"
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status after budget = %d, want 429", resp.StatusCode)
	}
}

func TestDisabledAccountCannotAuthenticate(t *testing.T) {
	h := newHarness(t, Options{}, config.Tenant{ID: "tenant", APIKeySHA256: digest("secret"), Disabled: true})
	resp := h.do(http.MethodPost, "/v1/claims", `{"client_id":"c"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestReadyzRevealsNoDiskDetails(t *testing.T) {
	h := newHarness(t, Options{})
	resp, err := http.Get(h.srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("Bytes")) {
		t.Fatalf("readyz = %d %s", resp.StatusCode, raw)
	}
}
