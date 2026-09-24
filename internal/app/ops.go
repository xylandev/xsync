package app

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/certstore"
	"github.com/xylandev/xsync/internal/metrics"
	"github.com/xylandev/xsync/internal/netguard"
	ftpadapter "github.com/xylandev/xsync/internal/protocol/ftp"
	sftpadapter "github.com/xylandev/xsync/internal/protocol/sftp"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

type opsDeps struct {
	store    *store.Store
	capacity *capacity.Controller
	tenants  *tenant.Registry
	metrics  *metrics.Registry
	token    string
	reload   func()
	draining func() bool
	log      *slog.Logger
}

// opsHandler serves the operator endpoints on the metrics listener:
// unauthenticated /metrics, /healthz and /readyz, and /admin/* behind the
// admin token. The listener binds to loopback by default.
func opsHandler(d opsDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		d.metrics.Write(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		s := d.capacity.Snapshot()
		switch {
		case d.draining():
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		case s.Critical:
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "critical_capacity"})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "reject_new_uploads": s.RejectNew, "throttled": s.Throttled})
		}
	})
	admin := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if d.token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(d.token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
				return
			}
			d.log.Info("admin request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery, "remote", r.RemoteAddr)
			h(w, r)
		})
	}
	admin("POST /admin/reload", func(w http.ResponseWriter, _ *http.Request) {
		d.reload()
		w.WriteHeader(http.StatusNoContent)
	})
	admin("GET /admin/tenants", func(w http.ResponseWriter, _ *http.Request) {
		stats := d.store.TenantStats()
		capSnap := d.capacity.Snapshot()
		type upload struct {
			BytesPerSecond float64 `json:"bytes_per_second"`
			// LimitBytesPerSecond is null while the account is unthrottled
			// (JSON has no infinity).
			LimitBytesPerSecond *float64 `json:"limit_bytes_per_second"`
			ActiveUploads       int      `json:"active_uploads"`
			SlotRejections      uint64   `json:"slot_rejections"`
		}
		type row struct {
			ID             string            `json:"id"`
			Disabled       bool              `json:"disabled"`
			Stats          store.TenantStats `json:"stats"`
			Upload         upload            `json:"upload"`
			OldestReadyAge float64           `json:"oldest_ready_age_seconds"`
		}
		out := []row{}
		for _, t := range d.tenants.Load().All() {
			c := capSnap.Tenants[t.ID]
			r := row{ID: t.ID, Disabled: t.Disabled, Stats: stats[t.ID], Upload: upload{BytesPerSecond: c.UploadBPS, ActiveUploads: c.ActiveUploads, SlotRejections: c.SlotRejections}}
			if !math.IsInf(c.UploadLimitBPS, 0) && !math.IsNaN(c.UploadLimitBPS) {
				limit := c.UploadLimitBPS
				r.Upload.LimitBytesPerSecond = &limit
			}
			if at, ok := d.store.OldestReady(t.ID); ok {
				r.OldestReadyAge = time.Since(at).Seconds()
			}
			out = append(out, r)
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
	})
	admin("GET /admin/parked", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		list, err := d.store.ListParked(r.URL.Query().Get("tenant"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"objects": list})
	})
	admin("POST /admin/objects/{id}/requeue", func(w http.ResponseWriter, r *http.Request) {
		respond(w, d.store.Requeue(r.URL.Query().Get("tenant"), r.PathValue("id")))
	})
	admin("DELETE /admin/objects/{id}", func(w http.ResponseWriter, r *http.Request) {
		respond(w, d.store.DeleteObject(r.URL.Query().Get("tenant"), r.PathValue("id"), "deleted-by-admin"))
	})
	admin("POST /admin/tenants/{id}/purge", func(w http.ResponseWriter, r *http.Request) {
		if d.tenants.Load().Active(r.PathValue("id")) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "disable or remove the account before purging its data"})
			return
		}
		n, err := d.store.PurgeTenant(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
	})
	admin("GET /admin/check", func(w http.ResponseWriter, _ *http.Request) {
		problems, err := d.store.Check()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"problems": problems})
	})
	admin("POST /admin/rebuild-indexes", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, d.store.RebuildIndexes())
	})
	return mux
}

func respond(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		status, raw = http.StatusInternalServerError, []byte(`{"error":"response encoding failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

type metricSources struct {
	store    *store.Store
	capacity *capacity.Controller
	tenants  *tenant.Registry
	certs    *certstore.Store
	auth     *netguard.AuthLimiter
	sftp     *sftpadapter.Server
	ftp      *ftpadapter.Server
	version  string
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// cached memoises an expensive value for ttl.
type cached struct {
	mu    sync.Mutex
	at    time.Time
	value float64
	ttl   time.Duration
	fn    func() float64
}

func (c *cached) get() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > c.ttl {
		c.value, c.at = c.fn(), time.Now()
	}
	return c.value
}

func registerMetrics(r *metrics.Registry, m metricSources) {
	gauge := func(name, help string, fn func() float64) {
		r.GaugeFunc(name, help, nil, func(emit func(float64, ...string)) { emit(fn()) })
	}
	snap := m.capacity.Snapshot
	gauge("xsync_disk_total_bytes", "Size of the data filesystem.", func() float64 { return float64(snap().TotalBytes) })
	gauge("xsync_disk_available_bytes", "Free bytes on the data filesystem.", func() float64 { return float64(snap().AvailableBytes) })
	gauge("xsync_disk_reserved_bytes", "Bytes reserved for server-side writes in progress.", func() float64 { return float64(snap().ReservedBytes) })
	gauge("xsync_disk_used_percent", "Used share of the data filesystem, including reservations.", func() float64 { return snap().UsedPercent })
	gauge("xsync_upload_bytes_per_second", "Smoothed upload rate.", func() float64 { return snap().UploadBPS })
	gauge("xsync_download_bytes_per_second", "Smoothed download rate.", func() float64 { return snap().DownloadBPS })
	gauge("xsync_delete_bytes_per_second", "Smoothed rate at which delivered data is deleted.", func() float64 { return snap().DeleteBPS })
	gauge("xsync_upload_limit_bytes_per_second", "Global upload budget; +Inf when unthrottled.", func() float64 { return snap().UploadLimitBPS })
	gauge("xsync_upload_throttled", "1 while the soft watermark throttles uploads.", func() float64 { return boolf(snap().Throttled) })
	gauge("xsync_uploads_rejected", "1 while new uploads are refused (hard watermark).", func() float64 { return boolf(snap().RejectNew) })
	gauge("xsync_capacity_critical", "1 while the disk is at the critical watermark.", func() float64 { return boolf(snap().Critical) })
	r.CounterFunc("xsync_statfs_errors_total", "Failed disk measurements.", nil, func(emit func(float64, ...string)) { emit(float64(snap().StatErrors)) })

	stats := func() store.Stats { s, _ := m.store.Stats(); return s }
	gauge("xsync_objects", "Objects in the catalog.", func() float64 { return float64(stats().Objects) })
	gauge("xsync_ready_objects", "Objects waiting for delivery.", func() float64 { return float64(stats().Ready) })
	gauge("xsync_leased_objects", "Objects being delivered.", func() float64 { return float64(stats().Leased) })
	gauge("xsync_held_objects", "Objects under a temporary name, waiting for a rename.", func() float64 { return float64(stats().Held) })
	gauge("xsync_parked_objects", "Dead-lettered objects that need attention.", func() float64 { return float64(stats().Parked) })
	gauge("xsync_delete_pending_objects", "Deleted objects whose blobs await garbage collection.", func() float64 { return float64(stats().DeletePending) })
	gauge("xsync_stored_bytes", "Bytes of published objects.", func() float64 { return float64(stats().Bytes) })
	gauge("xsync_upload_sessions", "Upload records, including interrupted and failed ones.", func() float64 { return float64(stats().Uploads) })
	gauge("xsync_active_uploads", "Uploads currently open.", func() float64 { return float64(m.store.InFlight()) })
	gauge("xsync_draining", "1 while the server is shutting down.", func() float64 { return boolf(m.store.Draining()) })
	staging := &cached{ttl: 30 * time.Second, fn: func() float64 { return float64(m.store.StagingBytes()) }}
	gauge("xsync_staging_bytes", "Bytes held by open, interrupted and failed uploads.", staging.get)
	gauge("xsync_tls_cert_not_after_seconds", "Expiry of the serving certificate as a Unix timestamp.", func() float64 { return float64(m.certs.NotAfter().Unix()) })
	r.CounterFunc("xsync_auth_failures_total", "Failed authentications on all protocols.", nil, func(emit func(float64, ...string)) { emit(float64(m.auth.Failures.Load())) })
	r.CounterFunc("xsync_auth_throttled_total", "Authentication attempts refused by the failure limiter.", nil, func(emit func(float64, ...string)) { emit(float64(m.auth.Blocked.Load())) })
	r.GaugeFunc("xsync_connections", "Open protocol connections.", []string{"protocol"}, func(emit func(float64, ...string)) {
		if m.sftp != nil {
			emit(float64(m.sftp.Active()), "sftp")
		}
		if m.ftp != nil {
			emit(float64(m.ftp.Active()), "ftp")
		}
	})
	r.GaugeFunc("xsync_build_info", "Build information.", []string{"version"}, func(emit func(float64, ...string)) { emit(1, m.version) })

	perTenant := func(name, help string, value func(id string, s store.TenantStats, c capacity.TenantSnapshot) float64) {
		r.GaugeFunc(name, help, []string{"tenant"}, func(emit func(float64, ...string)) {
			all := m.store.TenantStats()
			capSnap := snap()
			ids := make([]string, 0)
			for _, t := range m.tenants.Load().All() {
				ids = append(ids, t.ID)
			}
			sort.Strings(ids)
			for _, id := range ids {
				emit(value(id, all[id], capSnap.Tenants[id]), id)
			}
		})
	}
	perTenant("xsync_tenant_ready_objects", "Objects waiting for delivery, per account.", func(_ string, s store.TenantStats, _ capacity.TenantSnapshot) float64 { return float64(s.Ready) })
	perTenant("xsync_tenant_leased_objects", "Objects being delivered, per account.", func(_ string, s store.TenantStats, _ capacity.TenantSnapshot) float64 { return float64(s.Leased) })
	perTenant("xsync_tenant_parked_objects", "Dead-lettered objects, per account.", func(_ string, s store.TenantStats, _ capacity.TenantSnapshot) float64 { return float64(s.Parked) })
	perTenant("xsync_tenant_held_objects", "Objects under a temporary name, per account.", func(_ string, s store.TenantStats, _ capacity.TenantSnapshot) float64 { return float64(s.Held) })
	perTenant("xsync_tenant_stored_bytes", "Bytes of published objects, per account.", func(_ string, s store.TenantStats, _ capacity.TenantSnapshot) float64 { return float64(s.Bytes) })
	perTenant("xsync_tenant_upload_bytes_per_second", "Smoothed upload rate, per account.", func(_ string, _ store.TenantStats, c capacity.TenantSnapshot) float64 { return c.UploadBPS })
	perTenant("xsync_tenant_active_uploads", "Upload slots in use, per account.", func(_ string, _ store.TenantStats, c capacity.TenantSnapshot) float64 {
		return float64(c.ActiveUploads)
	})
	perTenant("xsync_tenant_upload_slot_rejections_total", "Uploads refused because every slot was busy, per account.", func(_ string, _ store.TenantStats, c capacity.TenantSnapshot) float64 {
		return float64(c.SlotRejections)
	})
	perTenant("xsync_tenant_oldest_ready_age_seconds", "Age of the oldest object waiting for delivery, per account.", func(id string, _ store.TenantStats, _ capacity.TenantSnapshot) float64 {
		if at, ok := m.store.OldestReady(id); ok {
			return time.Since(at).Seconds()
		}
		return 0
	})
}
