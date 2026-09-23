package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/xylandev/xsync/internal/api"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/platform"
	ftpadapter "github.com/xylandev/xsync/internal/protocol/ftp"
	s3adapter "github.com/xylandev/xsync/internal/protocol/s3"
	sftpadapter "github.com/xylandev/xsync/internal/protocol/sftp"
	"github.com/xylandev/xsync/internal/store"
)

func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if err := platform.ValidateDataDir(cfg.DataDir, cfg.RequireMount, cfg.Capacity.MinFreeBytes); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	capController := capacity.New(cfg.DataDir, cfg.Capacity, cfg.Tenants)
	capDone := make(chan struct{})
	go func() { defer close(capDone); capController.Run(ctx) }()
	st, err := store.Open(cfg.DataDir, capController, log)
	if err != nil {
		return err
	}
	defer st.Close()
	maintainDone := make(chan struct{})
	go func() { defer close(maintainDone); st.Maintain(ctx, 30*time.Second, cfg.PartialTTL) }()
	errCh := make(chan error, 5)
	var wg sync.WaitGroup
	start := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := fn(ctx); e != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("%s: %w", name, e)
			}
		}()
	}

	downloadServer := &http.Server{Addr: cfg.Download.Listen, Handler: api.New(st, capController, cfg.Tenants, log), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	start("download API", func(ctx context.Context) error {
		go func() {
			<-ctx.Done()
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = downloadServer.Shutdown(c)
		}()
		log.Info("download API listening", "addr", cfg.Download.Listen)
		e := downloadServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	})
	metricsServer := &http.Server{Addr: cfg.Metrics.Listen, Handler: metricsHandler(st, capController), ReadHeaderTimeout: 5 * time.Second}
	start("metrics", func(ctx context.Context) error {
		go func() { <-ctx.Done(); _ = metricsServer.Close() }()
		log.Info("metrics listening", "addr", cfg.Metrics.Listen)
		e := metricsServer.ListenAndServe()
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	})
	if cfg.SFTP.Enabled {
		srv := sftpadapter.New(cfg.SFTP, cfg.Tenants, st, log)
		start("sftp", srv.Serve)
	}
	if cfg.FTP.Enabled {
		srv := ftpadapter.New(cfg.FTP, cfg.TLS, cfg.Tenants, st, log)
		start("ftp", srv.Serve)
	}
	if cfg.S3.Enabled {
		srv := s3adapter.New(cfg.S3, cfg.TLS, cfg.Tenants, st, cfg.PartialTTL, log)
		start("s3", srv.Serve)
	}

	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	cancel()
	wg.Wait()
	<-capDone
	<-maintainDone
	return err
}

func metricsHandler(st *store.Store, cap *capacity.Controller) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		s := cap.Snapshot()
		db, _ := st.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "xsync_disk_total_bytes %d\nxsync_disk_available_bytes %d\nxsync_disk_used_percent %.4f\nxsync_upload_bytes_per_second %.4f\nxsync_download_bytes_per_second %.4f\nxsync_delete_bytes_per_second %.4f\nxsync_upload_limit_bytes_per_second %.4f\nxsync_objects %d\nxsync_ready_objects %d\nxsync_leased_objects %d\nxsync_delete_pending_objects %d\nxsync_active_uploads %d\n", s.TotalBytes, s.AvailableBytes, s.UsedPercent, s.UploadBPS, s.DownloadBPS, s.DeleteBPS, s.UploadLimitBPS, db.Objects, db.Ready, db.Leased, db.DeletePending, db.Uploads)
	})
	return mux
}
