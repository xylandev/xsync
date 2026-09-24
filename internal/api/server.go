// Package api serves the download API: downloaders claim objects, fetch them
// under a lease, and commit or release them.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/metrics"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

// Version is reported in the X-Xsync-API-Version header so clients can detect
// optional features.
const Version = "2"

type Options struct {
	MaxLease    time.Duration
	MaxLongPoll time.Duration
	MaxBatch    int
	IdleTimeout time.Duration
	Auth        *netguard.AuthLimiter
	Metrics     *metrics.Registry
	// Draining reports whether the server is shutting down.
	Draining func() bool
}

type Server struct {
	store    *store.Store
	cap      *capacity.Controller
	tenants  *tenant.Registry
	log      *slog.Logger
	opts     Options
	requests *metrics.CounterVec
	latency  *metrics.HistogramVec
	bytesOut *metrics.CounterVec
	commits  *metrics.CounterVec
	releases *metrics.CounterVec
}

func New(st *store.Store, cap *capacity.Controller, tenants *tenant.Registry, opts Options, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.MaxLease <= 0 {
		opts.MaxLease = time.Hour
	}
	if opts.MaxBatch <= 0 {
		opts.MaxBatch = 64
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	s := &Server{store: st, cap: cap, tenants: tenants, log: log, opts: opts}
	s.requests = opts.Metrics.CounterVec("xsync_api_requests_total", "Download API requests by route and status.", "route", "status")
	s.latency = opts.Metrics.HistogramVec("xsync_api_request_duration_seconds", "Download API request latency.", metrics.DefaultLatencyBuckets, "route")
	s.bytesOut = opts.Metrics.CounterVec("xsync_download_bytes_total", "Object bytes served to downloaders.", "tenant")
	s.commits = opts.Metrics.CounterVec("xsync_commits_total", "Committed deliveries.", "tenant", "result")
	s.releases = opts.Metrics.CounterVec("xsync_releases_total", "Leases given back without a commit.", "tenant", "kind")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", s.ready)
	route := func(pattern, name string, h http.HandlerFunc) {
		mux.Handle(pattern, s.instrument(name, s.auth(h)))
	}
	route("POST /v1/claims", "claim", s.claim)
	route("POST /v1/claims/{lease}/renew", "renew", s.renew)
	route("DELETE /v1/claims/{lease}", "release", s.release)
	route("POST /v1/claims/{lease}/release", "release", s.release)
	route("GET /v1/objects/{object}/content", "content", s.content)
	route("POST /v1/objects/{object}/commit", "commit", s.commit)
	route("GET /v1/parked", "parked", s.parked)
	route("POST /v1/objects/{object}/requeue", "requeue", s.requeue)
	route("DELETE /v1/objects/{object}", "delete", s.deleteObject)
	return netguard.StallGuard(opts.IdleTimeout, s.accessLog(mux))
}

type contextKey struct{}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.opts.Auth.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "throttled", netguard.ErrThrottled.Error())
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		t, found := s.tenants.Load().ByAPIKey(strings.TrimSpace(token))
		if !ok || !found {
			s.opts.Auth.Fail(ip)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid API key")
			return
		}
		// The authenticated tenant travels in the request context, not in a
		// header: headers are client-controlled input and must not share a
		// namespace with a server-side authorization decision.
		if rec, ok := w.(*recorder); ok {
			rec.tenant = t.ID
		}
		w.Header().Set("X-Xsync-API-Version", Version)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, t.ID)))
	})
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func tenantOf(r *http.Request) string {
	id, _ := r.Context().Value(contextKey{}).(string)
	return id
}

func (s *Server) instrument(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		status := http.StatusOK
		if rec, ok := w.(*recorder); ok {
			status = rec.status
		}
		s.requests.With(route, strconv.Itoa(status)).Inc()
		if route != "claim" { // long polls would drown the latency signal
			s.latency.With(route).Observe(time.Since(start).Seconds())
		}
	})
}

// accessLog wraps the ResponseWriter exactly once, so that the audit trail and
// the download byte accounting can coexist.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		// Health probes and empty polls are the bulk of traffic and carry no
		// information; keep them out of the default log level.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || rec.status == http.StatusNoContent && r.URL.Path == "/v1/claims" {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "download API request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.written, "tenant", rec.tenant, "remote", r.RemoteAddr,
			"duration", time.Since(start))
	})
}

// ready is unauthenticated, so it reports only a verdict, not disk details.
func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Draining != nil && s.opts.Draining() {
		writeError(w, http.StatusServiceUnavailable, "draining", "server is shutting down")
		return
	}
	if s.cap != nil && s.cap.Snapshot().Critical {
		writeError(w, http.StatusServiceUnavailable, "critical_capacity", "critical storage capacity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) clampLease(seconds int) time.Duration {
	if seconds <= 0 {
		return 2 * time.Minute
	}
	d := time.Duration(seconds) * time.Second
	if d < 10*time.Second {
		d = 10 * time.Second
	}
	if d > s.opts.MaxLease {
		d = s.opts.MaxLease
	}
	return d
}

func decodeBody(r *http.Request, limit int64, v any) error {
	if r.Body == nil {
		return nil
	}
	err := json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(v)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type claimRequest struct {
	ClientID     string `json:"client_id"`
	Prefix       string `json:"prefix"`
	LeaseSeconds int    `json:"lease_seconds"`
	// Max > 0 selects the batch response {"claims": [...]}. Without it the
	// response is a single claim, as in API version 1.
	Max         int `json:"max"`
	WaitSeconds int `json:"wait_seconds"`
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var req claimRequest
	if err := decodeBody(r, 64<<10, &req); err != nil || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "client_id is required")
		return
	}
	tenantID := tenantOf(r)
	batch := req.Max
	if batch <= 0 {
		batch = 1
	}
	if batch > s.opts.MaxBatch {
		batch = s.opts.MaxBatch
	}
	wait := time.Duration(req.WaitSeconds) * time.Second
	if wait > s.opts.MaxLongPoll {
		wait = s.opts.MaxLongPoll
	}
	deadline := time.Now().Add(wait)
	opts := store.ClaimOptions{ClientID: req.ClientID, Prefix: req.Prefix, TTL: s.clampLease(req.LeaseSeconds), Max: batch}
	for {
		// Subscribe before looking, so work published in between wakes us.
		wake := s.store.WaitForWork(tenantID)
		claims, err := s.store.Claim(tenantID, opts)
		if err == nil {
			if req.Max > 0 {
				writeJSON(w, http.StatusOK, map[string]any{"claims": claims})
			} else {
				writeJSON(w, http.StatusCreated, claims[0])
			}
			return
		}
		if !errors.Is(err, store.ErrNotFound) {
			s.storeError(w, r, err)
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || (s.opts.Draining != nil && s.opts.Draining()) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if next, ok := s.store.NextVisible(tenantID); ok && time.Until(next) < remaining {
			remaining = max0(time.Until(next))
		}
		timer := time.NewTimer(remaining)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func max0(d time.Duration) time.Duration {
	if d < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	return d
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseSeconds int `json:"lease_seconds"`
	}
	if err := decodeBody(r, 16<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid renew body")
		return
	}
	var ttl time.Duration
	if req.LeaseSeconds > 0 {
		ttl = s.clampLease(req.LeaseSeconds)
	}
	claim, err := s.store.Renew(tenantOf(r), r.PathValue("lease"), ttl)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

type releaseRequest struct {
	Reason            string `json:"reason"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
	Permanent         bool   `json:"permanent"`
	// CountAttempt=false returns the delivery attempt, for a downloader that
	// is shutting down rather than failing.
	CountAttempt *bool `json:"count_attempt"`
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := decodeBody(r, 16<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid release body")
		return
	}
	retry := time.Duration(req.RetryAfterSeconds) * time.Second
	if retry < 0 || retry > 24*time.Hour {
		writeError(w, http.StatusBadRequest, "bad_request", "retry_after_seconds must be between 0 and 86400")
		return
	}
	opts := store.ReleaseOptions{Reason: req.Reason, RetryAfter: retry, Permanent: req.Permanent, Uncounted: req.CountAttempt != nil && !*req.CountAttempt}
	if err := s.store.ReleaseWith(tenantOf(r), r.PathValue("lease"), opts); err != nil {
		s.storeError(w, r, err)
		return
	}
	kind := "retry"
	switch {
	case req.Permanent:
		kind = "permanent"
	case opts.Uncounted:
		kind = "shutdown"
	}
	s.releases.With(tenantOf(r), kind).Inc()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) content(w http.ResponseWriter, r *http.Request) {
	lease := r.Header.Get("X-Xsync-Lease-ID")
	if lease == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "X-Xsync-Lease-ID is required")
		return
	}
	f, o, err := s.store.OpenClaim(tenantOf(r), r.PathValue("object"), lease)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	defer f.Close()
	w.Header().Set("ETag", `"sha256:`+o.SHA256+`"`)
	w.Header().Set("X-Content-SHA256", o.SHA256)
	w.Header().Set("X-Xsync-Lease-Until", o.LeaseUntil.Format(time.RFC3339Nano))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepathBase(o.Path)))
	if rec, ok := w.(*recorder); ok {
		tenantBytes := s.bytesOut.With(o.Tenant)
		rec.observe = func(n int64) {
			tenantBytes.Add(float64(n))
			if s.cap != nil {
				s.cap.ObserveDownload(n)
			}
		}
	}
	http.ServeContent(w, r, filepathBase(o.Path), o.CreatedAt, f)
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseID string `json:"lease_id"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
	}
	if err := decodeBody(r, 16<<10, &req); err != nil || req.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid commit")
		return
	}
	deleted, err := s.store.Commit(tenantOf(r), r.PathValue("object"), req.LeaseID, req.SHA256, req.Size)
	if err != nil {
		s.commits.With(tenantOf(r), "rejected").Inc()
		s.storeError(w, r, err)
		return
	}
	result := "deleted"
	if !deleted {
		result = "duplicate"
	}
	s.commits.With(tenantOf(r), result).Inc()
	w.WriteHeader(http.StatusNoContent)
}

type objectView struct {
	ObjectID  string    `json:"object_id"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Version   uint64    `json:"version"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
	ParkedAt  time.Time `json:"parked_at"`
	CreatedAt time.Time `json:"created_at"`
}

func view(o model.ObjectVersion) objectView {
	return objectView{ObjectID: o.ID, Path: o.Path, Size: o.Size, SHA256: o.SHA256, Version: o.Version, Attempts: o.Attempts, LastError: o.LastError, ParkedAt: o.ParkedAt, CreatedAt: o.CreatedAt}
}

func (s *Server) parked(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.store.ListParked(tenantOf(r), limit)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	out := make([]objectView, 0, len(list))
	for _, o := range list {
		out = append(out, view(o))
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": out})
}

func (s *Server) requeue(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Requeue(tenantOf(r), r.PathValue("object")); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "not_parked", "only parked objects can be requeued")
			return
		}
		s.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteObject lets a downloader drop a parked object it has given up on.
func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request) {
	o, err := s.store.Object(r.PathValue("object"))
	if err != nil || o.Tenant != tenantOf(r) {
		writeError(w, http.StatusNotFound, "not_found", "object not found")
		return
	}
	if o.State != model.StateParked {
		writeError(w, http.StatusConflict, "not_parked", "only parked objects can be deleted through the download API")
		return
	}
	if err := s.store.DeleteObject(o.Tenant, o.ID, "dropped-by-downloader"); err != nil {
		s.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// recorder captures the status code and transferred size for the access log, and
// optionally reports content bytes to the capacity controller.
type recorder struct {
	http.ResponseWriter
	status  int
	written int64
	tenant  string
	observe func(int64)
	wrote   bool
}

func (w *recorder) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recorder) Write(p []byte) (int, error) {
	w.wrote = true
	n, err := w.ResponseWriter.Write(p)
	w.record(int64(n))
	return n, err
}

// ReadFrom keeps io.Copy from ServeContent on the underlying writer's fast
// path. Over TLS that is a buffered copy rather than sendfile, but it avoids
// an extra 32 KiB bounce buffer per request.
func (w *recorder) ReadFrom(r io.Reader) (int64, error) {
	w.wrote = true
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.record(n)
		return n, err
	}
	n, err := io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
	w.record(n)
	return n, err
}

func (w *recorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *recorder) record(n int64) {
	w.written += n
	if w.observe != nil && n > 0 {
		w.observe(n)
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// storeError maps store errors to API errors. Unexpected errors are logged in
// full but reported to the client without internal details.
func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, store.ErrLeaseMismatch):
		writeError(w, http.StatusConflict, "lease_mismatch", "the lease is no longer held")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusUnprocessableEntity, "digest_mismatch", "size or SHA-256 does not match the object")
	case errors.Is(err, store.ErrInvalidPath):
		writeError(w, http.StatusBadRequest, "bad_request", "invalid prefix")
	default:
		s.log.Error("download API internal error", "path", r.URL.Path, "tenant", tenantOf(r), "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": message, "code": code, "status": status})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		status, raw = http.StatusInternalServerError, []byte(`{"error":"response encoding failed","code":"internal","status":500}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}
