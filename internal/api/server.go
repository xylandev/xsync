package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	return mux
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
	var tenant string
	for digest, id := range h.server.keys {
		if len(digest) == len(encoded) && subtle.ConstantTimeCompare([]byte(digest), []byte(encoded)) == 1 {
			tenant = id
			break
		}
	}
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	r.Header.Set("X-Xsync-Tenant", tenant)
	h.next.ServeHTTP(w, r)
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	snap := s.cap.Snapshot()
	if snap.Critical {
		writeError(w, http.StatusServiceUnavailable, "critical storage capacity")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func tenant(r *http.Request) string { return r.Header.Get("X-Xsync-Tenant") }

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
	observer := &observedWriter{ResponseWriter: w, observe: s.cap.ObserveDownload}
	http.ServeContent(observer, r, filepathBase(o.Path), o.CreatedAt, f)
}

type observedWriter struct {
	http.ResponseWriter
	observe func(int)
}

func (w *observedWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.observe(n)
	return n, err
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

func ParseRangeOffset(value string) int64 {
	value = strings.TrimPrefix(value, "bytes=")
	value = strings.TrimSuffix(value, "-")
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}
