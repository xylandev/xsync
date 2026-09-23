package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
)

type Server struct {
	store *store.Store
	cap   *capacity.Controller
	log   *slog.Logger
	keys  map[string]string
}

func New(st *store.Store, cap *capacity.Controller, tenants []config.Tenant, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{store: st, cap: cap, log: log, keys: map[string]string{}}
	for _, t := range tenants {
		if t.APIKeySHA256 != "" {
			s.keys[strings.ToLower(t.APIKeySHA256)] = t.ID
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("POST /v1/claims", s.auth(http.HandlerFunc(s.claim)))
	mux.Handle("POST /v1/claims/{lease}/renew", s.auth(http.HandlerFunc(s.renew)))
	mux.Handle("DELETE /v1/claims/{lease}", s.auth(http.HandlerFunc(s.release)))
	mux.Handle("GET /v1/objects/{object}/content", s.auth(http.HandlerFunc(s.content)))
	mux.Handle("POST /v1/objects/{object}/commit", s.auth(http.HandlerFunc(s.commit)))
	return s.accessLog(mux)
}

type contextKey struct{}

type authHandler struct {
	next   http.Handler
	server *Server
}

func (s *Server) auth(next http.Handler) http.Handler { return authHandler{next: next, server: s} }
func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	sum := sha256.Sum256([]byte(token))
	encoded := hex.EncodeToString(sum[:])
	var tenantID string
	for digest, id := range h.server.keys {
		if len(digest) == len(encoded) && subtle.ConstantTimeCompare([]byte(digest), []byte(encoded)) == 1 {
			tenantID = id
			break
		}
	}
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	// The authenticated tenant travels in the request context, not in a header:
	// headers are client-controlled input and must not share a namespace with a
	// server-side authorization decision.
	if rec, ok := w.(*recorder); ok {
		rec.tenant = tenantID
	}
	h.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, tenantID)))
}

// accessLog wraps the ResponseWriter exactly once, so that the audit trail, the
// download byte accounting, and net/http's ReaderFrom fast path can coexist.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "download API request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.written, "tenant", rec.tenant, "remote", r.RemoteAddr,
			"duration", time.Since(start))
	})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	snap := s.cap.Snapshot()
	if snap.Critical {
		writeError(w, http.StatusServiceUnavailable, "critical storage capacity")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func tenant(r *http.Request) string {
	id, _ := r.Context().Value(contextKey{}).(string)
	return id
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"client_id"`
		Prefix       string `json:"prefix"`
		LeaseSeconds int    `json:"lease_seconds"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req) != nil || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if req.LeaseSeconds <= 0 {
		req.LeaseSeconds = 120
	}
	if req.LeaseSeconds > 3600 {
		req.LeaseSeconds = 3600
	}
	claim, err := s.store.ClaimNext(tenant(r), req.ClientID, req.Prefix, time.Duration(req.LeaseSeconds)*time.Second)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, claim)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseSeconds int `json:"lease_seconds"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req)
	claim, err := s.store.Renew(tenant(r), r.PathValue("lease"), time.Duration(req.LeaseSeconds)*time.Second)
	if err != nil {
		mapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Release(tenant(r), r.PathValue("lease")); err != nil {
		mapStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) content(w http.ResponseWriter, r *http.Request) {
	lease := r.Header.Get("X-Xsync-Lease-ID")
	if lease == "" {
		writeError(w, http.StatusBadRequest, "X-Xsync-Lease-ID is required")
		return
	}
	f, o, err := s.store.OpenClaim(tenant(r), r.PathValue("object"), lease)
	if err != nil {
		mapStoreError(w, err)
		return
	}
	defer f.Close()
	w.Header().Set("ETag", `"sha256:`+o.SHA256+`"`)
	w.Header().Set("X-Content-SHA256", o.SHA256)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepathBase(o.Path)))
	// Count only object content towards the capacity controller's drain estimate.
	if rec, ok := w.(*recorder); ok {
		rec.observe = s.cap.ObserveDownload
	}
	http.ServeContent(w, r, filepathBase(o.Path), o.CreatedAt, f)
}

// recorder captures the status code and transferred size for the access log, and
// optionally reports content bytes to the capacity controller.
//
// It deliberately forwards io.ReaderFrom: wrapping a ResponseWriter in a struct
// hides the underlying ReadFrom method, which would otherwise downgrade every
// download to a 32 KiB userspace copy loop instead of net/http's sendfile path.
type recorder struct {
	http.ResponseWriter
	status  int
	written int64
	tenant  string
	observe func(int64)
}

func (w *recorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *recorder) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.record(int64(n))
	return n, err
}

func (w *recorder) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.record(n)
		return n, err
	}
	// Copy into the bare ResponseWriter so this method is not re-entered.
	n, err := io.Copy(w.ResponseWriter, r)
	w.record(n)
	return n, err
}

func (w *recorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recorder) record(n int64) {
	w.written += n
	if w.observe != nil {
		w.observe(n)
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseID string `json:"lease_id"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req) != nil || req.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "invalid commit")
		return
	}
	deleted, err := s.store.Commit(tenant(r), r.PathValue("object"), req.LeaseID, req.SHA256, req.Size)
	if err != nil {
		mapStoreError(w, err)
		return
	}
	if deleted {
		s.cap.ObserveDelete(req.Size)
	}
	w.WriteHeader(http.StatusNoContent)
}

func mapStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrLeaseMismatch):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message, "status": status})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
