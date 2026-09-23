package ftpadapter

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
)

type Server struct {
	cfg     config.FTPConfig
	tls     config.TLSConfig
	tenants []config.Tenant
	store   *store.Store
	log     *slog.Logger
	server  *ftpserver.FtpServer
}

func New(cfg config.FTPConfig, tlsCfg config.TLSConfig, tenants []config.Tenant, st *store.Store, log *slog.Logger) *Server {
	return &Server{cfg: cfg, tls: tlsCfg, tenants: tenants, store: st, log: log}
}

func (s *Server) Serve(ctx context.Context) error {
	d := &driver{cfg: s.cfg, tls: s.tls, tenants: s.tenants, store: s.store, ctx: ctx}
	s.server = ftpserver.NewFtpServer(d)
	s.server.Logger = s.log
	go func() { <-ctx.Done(); _ = s.server.Stop() }()
	s.log.Info("FTP/FTPS listening", "addr", s.cfg.Listen)
	err := s.server.ListenAndServe()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type driver struct {
	cfg     config.FTPConfig
	tls     config.TLSConfig
	tenants []config.Tenant
	store   *store.Store
	ctx     context.Context
}

func (d *driver) GetSettings() (*ftpserver.Settings, error) {
	return &ftpserver.Settings{ListenAddr: d.cfg.Listen, PublicHost: d.cfg.PublicHost, PassiveTransferPortRange: &ftpserver.PortRange{Start: d.cfg.PassiveStart, End: d.cfg.PassiveEnd}, TLSRequired: ftpserver.ClearOrEncrypted, Banner: "xsync ready", EnableHASH: true, DisableASCIIConversion: true}, nil
}
func (d *driver) ClientConnected(ftpserver.ClientContext) (string, error) { return "xsync ready", nil }

// ClientDisconnected cancels the connection context so that a store operation
// parked on the capacity limiter stops waiting and frees the tenant's upload slot.
func (d *driver) ClientDisconnected(cc ftpserver.ClientContext) {
	if cancel, ok := cc.Extra().(context.CancelFunc); ok {
		cancel()
	}
}
func (d *driver) PreAuthUser(cc ftpserver.ClientContext, user string) error {
	for _, t := range d.tenants {
		if t.FTPUser == user {
			if t.AllowPlainFTP {
				return cc.SetTLSRequirement(ftpserver.ClearOrEncrypted)
			}
			return cc.SetTLSRequirement(ftpserver.MandatoryEncryption)
		}
	}
	return cc.SetTLSRequirement(ftpserver.MandatoryEncryption)
}
func (d *driver) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	for _, t := range d.tenants {
		if t.FTPUser == user && subtle.ConstantTimeCompare([]byte(t.FTPPassword), []byte(pass)) == 1 {
			ctx, cancel := context.WithCancel(d.ctx)
			cc.SetExtra(cancel)
			return &clientFS{tenant: t.ID, store: d.store, ctx: ctx}, nil
		}
	}
	return nil, errors.New("authentication failed")
}
func (d *driver) GetTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(d.tls.CertFile, d.tls.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

type clientFS struct {
	tenant string
	store  *store.Store
	ctx    context.Context
}

func (f *clientFS) Name() string { return "xsync" }
func (f *clientFS) Create(name string) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) Mkdir(name string, _ os.FileMode) error { return f.store.Mkdir(f.tenant, name) }
func (f *clientFS) MkdirAll(name string, _ os.FileMode) error {
	parts := strings.Split(strings.Trim(path.Clean(name), "/"), "/")
	current := ""
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		current = path.Join(current, p)
		if err := f.store.Mkdir(f.tenant, current); err != nil {
			return err
		}
	}
	return nil
}
func (f *clientFS) Open(name string) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) OpenFile(name string, flag int, _ os.FileMode) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) Remove(name string) error    { return f.store.Remove(f.tenant, name) }
func (f *clientFS) RemoveAll(name string) error { return f.store.Remove(f.tenant, name) }
func (f *clientFS) Rename(oldname, newname string) error {
	return f.store.Rename(f.tenant, oldname, newname)
}
func (f *clientFS) Stat(name string) (os.FileInfo, error) {
	clean := strings.Trim(path.Clean(name), "/")
	if clean == "" || clean == "." {
		return info{name: "/", dir: true, mode: os.ModeDir | 0o750, mod: time.Now()}, nil
	}
	o, err := f.store.Current(f.tenant, clean)
	if err == nil {
		return info{name: path.Base(clean), size: o.Size, mode: 0o640, mod: o.CreatedAt}, nil
	}
	exists, listErr := f.store.DirectoryExists(f.tenant, clean)
	if listErr == nil && exists {
		return info{name: path.Base(clean), dir: true, mode: os.ModeDir | 0o750, mod: time.Now()}, nil
	}
	return nil, err
}
func (f *clientFS) Chmod(string, os.FileMode) error            { return nil }
func (f *clientFS) Chown(string, int, int) error               { return nil }
func (f *clientFS) Chtimes(string, time.Time, time.Time) error { return nil }
func (f *clientFS) ReadDir(name string) ([]os.FileInfo, error) {
	entries, err := f.store.List(f.tenant, name)
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		if e.Directory {
			out = append(out, info{name: path.Base(e.Path), dir: true, mode: os.ModeDir | 0o750, mod: time.Now()})
		} else {
			out = append(out, info{name: path.Base(e.Path), size: e.Object.Size, mode: 0o640, mod: e.Object.CreatedAt})
		}
	}
	return out, nil
}
func (f *clientFS) RemoveDir(name string) error { return f.store.RemoveDir(f.tenant, name) }
func (f *clientFS) GetAvailableSpace(string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(f.store.Root(), &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}
func (f *clientFS) GetHandle(name string, flags int, offset int64) (ftpserver.FileTransfer, error) {
	if flags&os.O_WRONLY != 0 || flags&os.O_RDWR != 0 {
		var h *store.UploadHandle
		var err error
		if offset > 0 || flags&os.O_APPEND != 0 {
			h, err = f.store.BeginUploadFromCurrent(f.ctx, f.tenant, name, "ftp")
		} else {
			h, err = f.store.BeginUpload(f.ctx, f.tenant, name, "ftp")
		}
		if err != nil {
			if errors.Is(err, store.ErrUploadBlocked) {
				return nil, ftpserver.ErrStorageExceeded
			}
			return nil, err
		}
		return &uploadTransfer{handle: h, offset: offset}, nil
	}
	file, _, err := f.store.OpenCurrent(f.tenant, name)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		_, err = file.Seek(offset, io.SeekStart)
	}
	return file, err
}

type uploadTransfer struct {
	handle      *store.UploadHandle
	offset      int64
	transferErr error
}

func (u *uploadTransfer) Read([]byte) (int, error) { return 0, errors.New("write-only") }
func (u *uploadTransfer) Write(p []byte) (int, error) {
	n, err := u.handle.WriteAt(p, u.offset)
	u.offset += int64(n)
	if errors.Is(err, capacity.ErrCriticalCapacity) || errors.Is(err, store.ErrUploadBlocked) {
		return n, ftpserver.ErrStorageExceeded
	}
	return n, err
}
func (u *uploadTransfer) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		u.offset = off
	case io.SeekCurrent:
		u.offset += off
	default:
		return 0, errors.New("seek from end unsupported")
	}
	if u.offset < 0 {
		return 0, errors.New("negative offset")
	}
	return u.offset, nil
}
func (u *uploadTransfer) Close() error {
	if u.transferErr != nil {
		u.handle.TransferError(u.transferErr)
	}
	return u.handle.Close()
}
func (u *uploadTransfer) TransferError(err error) { u.transferErr = err; u.handle.TransferError(err) }

type info struct {
	name string
	size int64
	mode os.FileMode
	mod  time.Time
	dir  bool
}

func (i info) Name() string       { return i.name }
func (i info) Size() int64        { return i.size }
func (i info) Mode() os.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return i.mod }
func (i info) IsDir() bool        { return i.dir }
func (i info) Sys() any           { return nil }
