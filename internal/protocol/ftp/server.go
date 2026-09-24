package ftpadapter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/certstore"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

type Options struct {
	Limits config.LimitsConfig
	Auth   *netguard.AuthLimiter
	Certs  *certstore.Store
}

type Server struct {
	cfg     config.FTPConfig
	tenants *tenant.Registry
	store   *store.Store
	log     *slog.Logger
	opts    Options

	mu      sync.Mutex
	server  *ftpserver.FtpServer
	clients map[uint32]ftpserver.ClientContext
}

func New(cfg config.FTPConfig, tenants *tenant.Registry, st *store.Store, opts Options, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Limits.MaxConnections <= 0 {
		opts.Limits = config.Default().Limits
	}
	return &Server{cfg: cfg, tenants: tenants, store: st, log: log, opts: opts, clients: map[uint32]ftpserver.ClientContext{}}
}

// Serve accepts control connections until ctx ends; running sessions continue
// until Abort.
func (s *Server) Serve(ctx context.Context) error {
	inner, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	// ftpserverlib manages control-connection deadlines itself (IdleTimeout),
	// so the guard only limits connection counts.
	ln := netguard.NewListener(inner, netguard.Limits{MaxConns: s.opts.Limits.MaxConnections, MaxConnsPerIP: s.opts.Limits.MaxConnectionsPerIP})
	d := &driver{srv: s, listener: ln}
	server := ftpserver.NewFtpServer(d)
	server.Logger = s.log
	s.mu.Lock()
	s.server = server
	s.mu.Unlock()
	go func() { <-ctx.Done(); _ = server.Stop() }()
	s.log.Info("FTP/FTPS listening", "addr", s.cfg.Listen)
	err = server.ListenAndServe()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Active returns the number of connected FTP clients.
func (s *Server) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// Abort disconnects every client. Transfers in progress become resumable
// partials.
func (s *Server) Abort() {
	s.mu.Lock()
	clients := make([]ftpserver.ClientContext, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}

type driver struct {
	srv      *Server
	listener net.Listener
}

func (d *driver) GetSettings() (*ftpserver.Settings, error) {
	c := d.srv.cfg
	return &ftpserver.Settings{
		Listener: d.listener, ListenAddr: c.Listen, PublicHost: c.PublicHost,
		PassiveTransferPortRange: &ftpserver.PortRange{Start: c.PassiveStart, End: c.PassiveEnd},
		TLSRequired:              ftpserver.ClearOrEncrypted, Banner: "xsync ready",
		IdleTimeout:       int(d.srv.opts.Limits.IdleTimeout / time.Second),
		ConnectionTimeout: int(d.srv.opts.Limits.HandshakeTimeout / time.Second),
		EnableHASH:        true, DisableASCIIConversion: true, DisableActiveMode: true, DisableSite: true,
	}, nil
}

type session struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (d *driver) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cc.SetExtra(&session{ctx: ctx, cancel: cancel})
	d.srv.mu.Lock()
	d.srv.clients[cc.ID()] = cc
	d.srv.mu.Unlock()
	return "xsync ready", nil
}

// ClientDisconnected cancels the connection context so that a store operation
// parked on the capacity limiter stops waiting and frees the tenant's upload
// slot, and so that an upload whose control connection vanished is not
// published.
func (d *driver) ClientDisconnected(cc ftpserver.ClientContext) {
	if s, ok := cc.Extra().(*session); ok {
		s.cancel()
	}
	d.srv.mu.Lock()
	delete(d.srv.clients, cc.ID())
	d.srv.mu.Unlock()
}

func (d *driver) PreAuthUser(cc ftpserver.ClientContext, user string) error {
	if t, ok := d.srv.tenants.Load().ByFTPUser(user); ok && t.AllowPlainFTP {
		return cc.SetTLSRequirement(ftpserver.ClearOrEncrypted)
	}
	// Mandatory encryption also forces PROT P on the data channel.
	return cc.SetTLSRequirement(ftpserver.MandatoryEncryption)
}

func (d *driver) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	ip := netguard.HostOf(cc.RemoteAddr())
	if !d.srv.opts.Auth.Allow(ip) {
		return nil, netguard.ErrThrottled
	}
	t, ok := d.srv.tenants.Load().ByFTPUser(user)
	if !ok || !config.VerifySecret(pass, t.FTPPasswordHash, t.FTPPassword) {
		d.srv.opts.Auth.Fail(ip)
		return nil, errors.New("authentication failed")
	}
	sess, _ := cc.Extra().(*session)
	ctx := context.Background()
	if sess != nil {
		ctx = sess.ctx
	}
	return &clientFS{srv: d.srv, tenant: t.ID, ctx: ctx}, nil
}

func (d *driver) GetTLSConfig() (*tls.Config, error) {
	if d.srv.opts.Certs == nil {
		return nil, errors.New("TLS is not configured")
	}
	return d.srv.opts.Certs.TLSConfig(), nil
}

type clientFS struct {
	srv    *Server
	tenant string
	ctx    context.Context

	mu        sync.Mutex
	allocated int64 // size announced with ALLO for the next upload, or -1
}

func (f *clientFS) active() error {
	if !f.srv.tenants.Load().Active(f.tenant) {
		return os.ErrPermission
	}
	return nil
}

// mapError turns store errors into errors ftpserverlib reports with a
// meaningful reply code.
func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, capacity.ErrCriticalCapacity), errors.Is(err, store.ErrUploadBlocked), errors.Is(err, store.ErrQuota):
		return ftpserver.ErrStorageExceeded
	case errors.Is(err, store.ErrDraining), errors.Is(err, capacity.ErrTooManyUploads):
		return fmt.Errorf("%s (retry later)", err.Error())
	}
	return err
}

func (f *clientFS) Name() string { return "xsync" }
func (f *clientFS) Create(string) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) Mkdir(name string, _ os.FileMode) error {
	if err := f.active(); err != nil {
		return err
	}
	return mapError(f.srv.store.Mkdir(f.tenant, name))
}
func (f *clientFS) MkdirAll(name string, _ os.FileMode) error {
	if err := f.active(); err != nil {
		return err
	}
	current := ""
	for _, p := range strings.Split(strings.Trim(path.Clean(name), "/"), "/") {
		if p == "" || p == "." {
			continue
		}
		current = path.Join(current, p)
		if err := f.srv.store.Mkdir(f.tenant, current); err != nil {
			return mapError(err)
		}
	}
	return nil
}
func (f *clientFS) Open(string) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) OpenFile(string, int, os.FileMode) (afero.File, error) {
	return nil, errors.New("use transfer handle")
}
func (f *clientFS) Remove(name string) error {
	if err := f.active(); err != nil {
		return err
	}
	return mapError(f.srv.store.Remove(f.tenant, name))
}
func (f *clientFS) RemoveAll(name string) error { return f.Remove(name) }

// Rename follows rename(2): an existing destination file is replaced.
func (f *clientFS) Rename(oldname, newname string) error {
	if err := f.active(); err != nil {
		return err
	}
	return mapError(f.srv.store.RenameWith(f.tenant, oldname, newname, true))
}

func (f *clientFS) Stat(name string) (os.FileInfo, error) {
	if err := f.active(); err != nil {
		return nil, err
	}
	fi, err := f.srv.store.Stat(f.tenant, name)
	if err != nil {
		return nil, mapError(err)
	}
	base := path.Base("/" + fi.Path)
	if fi.Directory {
		return info{name: base, dir: true, mode: os.ModeDir | 0o750, mod: fi.ModTime}, nil
	}
	// A partial upload is reported with the size a REST resume continues from.
	return info{name: base, size: fi.Size, mode: 0o640, mod: fi.ModTime}, nil
}
func (f *clientFS) Chmod(string, os.FileMode) error            { return nil }
func (f *clientFS) Chown(string, int, int) error               { return nil }
func (f *clientFS) Chtimes(string, time.Time, time.Time) error { return nil }
func (f *clientFS) ReadDir(name string) ([]os.FileInfo, error) {
	if err := f.active(); err != nil {
		return nil, err
	}
	entries, err := f.srv.store.List(f.tenant, name)
	if err != nil {
		return nil, mapError(err)
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
func (f *clientFS) RemoveDir(name string) error {
	if err := f.active(); err != nil {
		return err
	}
	return mapError(f.srv.store.RemoveDir(f.tenant, name))
}
func (f *clientFS) GetAvailableSpace(string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(f.srv.store.Root(), &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

// AllocateSpace records the size announced by ALLO. The next upload must
// deliver exactly that many bytes, which lets careful clients protect
// themselves against FTP's inability to signal a truncated transfer.
func (f *clientFS) AllocateSpace(size int) error {
	f.mu.Lock()
	f.allocated = int64(size)
	f.mu.Unlock()
	return nil
}

func (f *clientFS) GetHandle(name string, flags int, offset int64) (ftpserver.FileTransfer, error) {
	if err := f.active(); err != nil {
		return nil, err
	}
	if flags&(os.O_WRONLY|os.O_RDWR) == 0 {
		file, _, err := f.srv.store.OpenCurrent(f.tenant, name)
		if err != nil {
			return nil, mapError(err)
		}
		if offset > 0 {
			if _, err = file.Seek(offset, io.SeekStart); err != nil {
				file.Close()
				return nil, err
			}
		}
		return file, nil
	}
	mode := store.ModeTruncate
	switch {
	case flags&os.O_APPEND != 0:
		mode = store.ModeAppend
	case flags&os.O_TRUNC == 0:
		// STOR after REST: continue from the offset the client asked for.
		mode = store.ModeResume
	}
	h, err := f.srv.store.OpenUpload(f.ctx, f.tenant, name, "ftp", mode)
	if err != nil {
		return nil, mapError(err)
	}
	f.mu.Lock()
	expect := f.allocated
	f.allocated = 0
	f.mu.Unlock()
	return &uploadTransfer{handle: h, ctx: f.ctx, grace: f.srv.cfg.CloseGrace, appendMode: mode == store.ModeAppend, expect: expect}, nil
}

type uploadTransfer struct {
	handle      *store.UploadHandle
	ctx         context.Context
	grace       time.Duration
	appendMode  bool
	offset      int64
	written     int64
	expect      int64
	transferErr error
}

func (u *uploadTransfer) Read([]byte) (int, error) { return 0, errors.New("write-only") }

func (u *uploadTransfer) Write(p []byte) (int, error) {
	var n int
	var err error
	if u.appendMode {
		n, err = u.handle.Append(p)
	} else {
		n, err = u.handle.WriteAt(p, u.offset)
	}
	u.offset += int64(n)
	u.written += int64(n)
	return n, mapError(err)
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

// Close publishes the upload. FTP stream mode ends a transfer by closing the
// data connection, which looks the same whether the client finished or
// crashed. A control connection that is gone, or goes away within the grace
// period, means the client never saw the transfer complete, so the upload is
// kept as a resumable partial instead of being delivered truncated.
func (u *uploadTransfer) Close() error {
	if u.transferErr == nil && u.expect > 0 && u.written != u.expect {
		u.transferErr = fmt.Errorf("received %d bytes, ALLO announced %d", u.written, u.expect)
	}
	if u.transferErr == nil && u.grace > 0 {
		t := time.NewTimer(u.grace)
		select {
		case <-u.ctx.Done():
			u.transferErr = errors.New("control connection closed before the transfer was confirmed")
		case <-t.C:
		}
		t.Stop()
	}
	if u.transferErr == nil && u.ctx.Err() != nil {
		u.transferErr = errors.New("control connection closed before the transfer was confirmed")
	}
	if u.transferErr != nil {
		u.handle.TransferError(u.transferErr)
	}
	return mapError(u.handle.Close())
}

func (u *uploadTransfer) TransferError(err error) {
	u.transferErr = err
	u.handle.TransferError(err)
}

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
