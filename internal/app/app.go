// Package app wires the server together and owns its lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xylandev/xsync/internal/api"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/certstore"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/metrics"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/platform"
	ftpadapter "github.com/xylandev/xsync/internal/protocol/ftp"
	s3adapter "github.com/xylandev/xsync/internal/protocol/s3"
	sftpadapter "github.com/xylandev/xsync/internal/protocol/sftp"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

// Options carries process-level inputs that are not configuration.
type Options struct {
	// Reload receives a value when accounts and certificates should be
	// reloaded (SIGHUP).
	Reload  <-chan struct{}
	Version string
}

func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	return RunWithOptions(ctx, cfg, log, Options{})
}

// policyFor maps an account to the store's delivery policy.
func policyFor(reg *tenant.Registry, defaults config.DeliveryConfig) func(string) store.Policy {
	return func(id string) store.Policy {
		t, _ := reg.Load().Get(id)
		max := t.MaxAttempts
		if max <= 0 {
			max = defaults.MaxAttempts
		}
		return store.Policy{
			Supersede:      t.EffectiveOverwrite() == config.OverwriteSupersede,
			HoldPatterns:   t.EffectiveHoldPatterns(),
			PublishDelay:   t.PublishDelay,
			MaxAttempts:    max,
			MaxStoredBytes: t.MaxStoredBytes,
		}
	}
}

type server struct {
	name  string
	serve func(context.Context) error
	// drain stops accepting work and waits (bounded by ctx) for requests in
	// flight; abort ends whatever is left.
	drain func(context.Context)
	abort func()
}

func RunWithOptions(ctx context.Context, cfg config.Config, log *slog.Logger, opts Options) error {
	report, err := platform.CheckDataDir(cfg.DataDir, cfg.RequireMount, cfg.DataVolumeID, cfg.Capacity.MinFreeBytes)
	if err != nil {
		return err
	}
	for _, w := range report.Warnings {
		log.Warn(w)
	}
	reg := tenant.NewRegistry(cfg.Tenants)
	capController := capacity.New(cfg.DataDir, cfg.Capacity, cfg.Tenants)
	reg.Subscribe(func(s *tenant.Snapshot) { capController.SyncTenants(s.All()) })
	capController.Sample()

	st, err := store.OpenWithOptions(cfg.DataDir, store.Options{Gate: capController, Log: log, Policy: policyFor(reg, cfg.Delivery), TombstoneTTL: cfg.Delivery.TombstoneTTL})
	if err != nil {
		return err
	}
	certs, err := certstore.New(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		st.Close()
		return err
	}
	if left := time.Until(certs.NotAfter()); left < 30*24*time.Hour {
		log.Warn("TLS certificate expires soon; run 'xsync-server cert renew'", "not_after", certs.NotAfter())
	}

	runCtx, stopBackground := context.WithCancel(context.Background())
	var background sync.WaitGroup
	goBackground := func(fn func()) {
		background.Add(1)
		go func() { defer background.Done(); fn() }()
	}
	goBackground(func() { capController.Run(runCtx) })
	goBackground(func() {
		st.MaintainWith(runCtx, store.MaintainOptions{
			Interval: 30 * time.Second, PartialTTL: cfg.PartialTTL,
			// Under disk pressure abandoned partials give way sooner.
			PressureTTL: time.Hour, Pressure: func() bool { return capController.Snapshot().RejectNew },
		})
	})
	reload := func(reason string) {
		tenants, err := cfg.LoadAccounts()
		if err != nil {
			log.Error("account reload failed; keeping the current accounts", "reason", reason, "error", err)
			return
		}
		reg.Replace(tenants)
		if err := certs.Reload(); err != nil {
			log.Error("certificate reload failed", "error", err)
		}
		log.Info("accounts reloaded", "reason", reason, "accounts", len(tenants))
	}
	goBackground(func() { watchAccounts(runCtx, cfg, opts.Reload, reload) })

	auth := netguard.NewAuthLimiter(cfg.Limits.AuthFailuresPerMinute)
	reg2 := metrics.New()
	draining := func() bool { return st.Draining() }

	var servers []server
	apiHandler := api.New(st, capController, reg, api.Options{MaxLease: cfg.Delivery.MaxLease, MaxLongPoll: cfg.Delivery.MaxLongPoll, MaxBatch: cfg.Delivery.MaxBatch, IdleTimeout: cfg.Limits.IdleTimeout, Auth: auth, Metrics: reg2, Draining: draining}, log)
	servers = append(servers, httpServer("download API", cfg.Download.Listen, apiHandler, certs, cfg.Limits, log))
	var sftpSrv *sftpadapter.Server
	var ftpSrv *ftpadapter.Server
	if cfg.SFTP.Enabled {
		sftpSrv = sftpadapter.New(cfg.SFTP, reg, st, sftpadapter.Options{Limits: cfg.Limits, Auth: auth}, log)
		servers = append(servers, server{name: "sftp", serve: sftpSrv.Serve, drain: func(context.Context) {}, abort: sftpSrv.Abort})
	}
	if cfg.FTP.Enabled {
		ftpSrv = ftpadapter.New(cfg.FTP, reg, st, ftpadapter.Options{Limits: cfg.Limits, Auth: auth, Certs: certs}, log)
		servers = append(servers, server{name: "ftp", serve: ftpSrv.Serve, drain: func(context.Context) {}, abort: ftpSrv.Abort})
	}
	if cfg.S3.Enabled {
		s3Srv := s3adapter.New(cfg.S3, reg, st, s3adapter.Options{Limits: cfg.Limits, Auth: auth, Certs: certs, PartialTTL: cfg.PartialTTL}, log)
		servers = append(servers, server{name: "s3", serve: s3Srv.Serve, drain: func(c context.Context) { _ = s3Srv.Shutdown(c) }, abort: s3Srv.Abort})
	}
	registerMetrics(reg2, metricSources{store: st, capacity: capController, tenants: reg, certs: certs, auth: auth, sftp: sftpSrv, ftp: ftpSrv, version: opts.Version})
	adminToken := ""
	if p := cfg.AdminTokenPath(); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			adminToken = strings.TrimSpace(string(raw))
		} else {
			log.Warn("admin token file unreadable; admin API disabled", "error", err)
		}
	}
	if cfg.Metrics.Listen != "" {
		ops := opsHandler(opsDeps{store: st, capacity: capController, tenants: reg, metrics: reg2, token: adminToken, reload: func() { reload("admin API") }, draining: draining, log: log})
		servers = append(servers, plainHTTPServer("metrics", cfg.Metrics.Listen, ops, log))
	}

	acceptCtx, stopAccepting := context.WithCancel(context.Background())
	errCh := make(chan error, len(servers))
	var running sync.WaitGroup
	for _, s := range servers {
		running.Add(1)
		go func(s server) {
			defer running.Done()
			if err := s.serve(acceptCtx); err != nil && acceptCtx.Err() == nil {
				errCh <- fmt.Errorf("%s: %w", s.name, err)
			}
		}(s)
	}
	log.Info("xsync server started", "version", opts.Version, "accounts", len(cfg.Tenants), "drain_only", report.LowSpace)

	select {
	case <-ctx.Done():
	case err = <-errCh:
		log.Error("listener failed; shutting down", "error", err)
	}

	// Phase one: stop taking new work. Uploads and downloads in flight may
	// finish within the grace period.
	log.Info("draining", "grace", cfg.ShutdownGrace, "uploads_in_flight", st.InFlight())
	st.Drain()
	stopAccepting()
	graceCtx, cancelGrace := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	var drained sync.WaitGroup
	for _, s := range servers {
		drained.Add(1)
		go func(s server) { defer drained.Done(); s.drain(graceCtx) }(s)
	}
	drained.Add(1)
	go func() { defer drained.Done(); _ = st.WaitIdle(graceCtx) }()
	drained.Wait()
	cancelGrace()
	// Phase two: end whatever is left. Open uploads become resumable
	// partials; interrupted downloads are redelivered after their lease.
	if n := st.InFlight(); n > 0 {
		log.Warn("grace period over; aborting remaining transfers", "uploads_in_flight", n)
	}
	for _, s := range servers {
		s.abort()
	}
	running.Wait()
	abortCtx, cancelAbort := context.WithTimeout(context.Background(), 5*time.Second)
	_ = st.WaitIdle(abortCtx)
	cancelAbort()
	stopBackground()
	background.Wait()
	if cerr := st.Close(); cerr != nil && err == nil {
		err = cerr
	}
	log.Info("xsync server stopped")
	return err
}

// watchAccounts reloads the account table on SIGHUP and when the accounts
// file changes, so `account add` and friends take effect without a restart.
func watchAccounts(ctx context.Context, cfg config.Config, signal <-chan struct{}, reload func(string)) {
	path := cfg.ResolvedAccountsFile()
	if path == "" {
		path = cfg.Path()
	}
	modTime := func() time.Time {
		if st, err := os.Stat(path); err == nil {
			return st.ModTime()
		}
		return time.Time{}
	}
	last := modTime()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-signal:
			last = modTime()
			reload("signal")
		case <-t.C:
			if m := modTime(); !m.Equal(last) {
				last = m
				reload("accounts file changed")
			}
		}
	}
}

func httpServer(name, addr string, h http.Handler, certs *certstore.Store, limits config.LimitsConfig, log *slog.Logger) server {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: certs.TLSConfig(), MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	return server{
		name: name,
		serve: func(ctx context.Context) error {
			inner, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			ln := netguard.NewListener(inner, netguard.Limits{MaxConns: limits.MaxConnections, MaxConnsPerIP: limits.MaxConnectionsPerIP})
			go func() { <-ctx.Done(); _ = ln.Close() }()
			log.Info(name+" listening", "addr", addr)
			err = srv.ServeTLS(ln, "", "")
			if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		},
		drain: func(ctx context.Context) { _ = srv.Shutdown(ctx) },
		abort: func() { _ = srv.Close() },
	}
}

func plainHTTPServer(name, addr string, h http.Handler, log *slog.Logger) server {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	return server{
		name: name,
		serve: func(ctx context.Context) error {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			log.Info(name+" listening", "addr", addr)
			// It keeps serving until abort, not until accepting stops, so
			// the drain itself can be observed.
			err = srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
		drain: func(context.Context) {},
		abort: func() { _ = srv.Close() },
	}
}
