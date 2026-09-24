package sftpadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
	"golang.org/x/crypto/ssh"
)

type Options struct {
	Limits config.LimitsConfig
	Auth   *netguard.AuthLimiter
}

type Server struct {
	cfg     config.SFTPConfig
	tenants *tenant.Registry
	store   *store.Store
	log     *slog.Logger
	opts    Options

	mu       sync.Mutex
	listener *netguard.Listener
	conns    map[net.Conn]struct{}
	sessions sync.WaitGroup
}

func New(cfg config.SFTPConfig, tenants *tenant.Registry, st *store.Store, opts Options, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Limits.MaxOpenFilesPerSession <= 0 {
		opts.Limits = config.Default().Limits
	}
	return &Server{cfg: cfg, tenants: tenants, store: st, log: log, opts: opts, conns: map[net.Conn]struct{}{}}
}

func (s *Server) sshConfig() (*ssh.ServerConfig, error) {
	hostKey, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read SFTP host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return nil, fmt.Errorf("parse SFTP host key: %w", err)
	}
	cfg := &ssh.ServerConfig{MaxAuthTries: 6, ServerVersion: "SSH-2.0-xsync"}
	authorized := func(meta ssh.ConnMetadata, ok func(config.Tenant) bool) (*ssh.Permissions, error) {
		ip := netguard.HostOf(meta.RemoteAddr())
		if !s.opts.Auth.Allow(ip) {
			return nil, netguard.ErrThrottled
		}
		t, found := s.tenants.Load().BySFTPUser(meta.User())
		if !found || !ok(t) {
			s.opts.Auth.Fail(ip)
			return nil, errors.New("authentication failed")
		}
		return &ssh.Permissions{Extensions: map[string]string{"tenant": t.ID}}, nil
	}
	cfg.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		return authorized(meta, func(t config.Tenant) bool {
			return config.VerifySecret(string(password), t.SFTPPasswordHash, t.SFTPPassword)
		})
	}
	cfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return authorized(meta, func(t config.Tenant) bool {
			for _, raw := range t.AuthorizedKeys {
				k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
				if err == nil && bytes.Equal(k.Marshal(), key.Marshal()) {
					return true
				}
			}
			return false
		})
	}
	cfg.AddHostKey(signer)
	return cfg, nil
}

// Serve accepts connections until ctx ends. Sessions already running keep
// going; Abort ends them.
func (s *Server) Serve(ctx context.Context) error {
	cfg, err := s.sshConfig()
	if err != nil {
		return err
	}
	inner, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	ln := netguard.NewListener(inner, netguard.Limits{MaxConns: s.opts.Limits.MaxConnections, MaxConnsPerIP: s.opts.Limits.MaxConnectionsPerIP, IdleTimeout: s.opts.Limits.IdleTimeout})
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	s.log.Info("SFTP listening", "addr", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("SFTP accept", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.track(conn, true)
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			defer s.track(conn, false)
			s.handle(conn, cfg)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// Active returns the number of open SFTP connections.
func (s *Server) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Abort closes every open connection and waits for their sessions to end.
// Uploads still open become resumable partials.
func (s *Server) Abort() {
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.sessions.Wait()
}

func (s *Server) handle(raw net.Conn, cfg *ssh.ServerConfig) {
	defer raw.Close()
	// Bound the unauthenticated phase independently of the idle timeout, so
	// a peer that trickles bytes cannot hold a connection open forever.
	timer := time.AfterFunc(s.opts.Limits.HandshakeTimeout, func() { _ = raw.Close() })
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if !timer.Stop() && err == nil {
		err = errors.New("handshake timed out")
	}
	if err != nil {
		s.log.Debug("SFTP handshake", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	defer conn.Close()
	tenantID := conn.Permissions.Extensions["tenant"]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Store waits (slot, rate limit) must end when the client goes away.
	go func() { _ = conn.Wait(); cancel() }()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		okCh := make(chan bool, 1)
		go func() {
			accepted := false
			for req := range requests {
				ok := !accepted && req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if ok {
					accepted = true
					okCh <- true
				}
			}
			close(okCh)
		}()
		if ok := <-okCh; !ok {
			channel.Close()
			continue
		}
		h := &handler{ctx: ctx, tenant: tenantID, tenants: s.tenants, store: s.store, maxOpen: s.opts.Limits.MaxOpenFilesPerSession, open: map[string]*upload{}}
		rs := sftp.NewRequestServer(channel, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}, sftp.WithRSAllocator(), sftp.WithRSMaxTxPacket(1<<20))
		go func() {
			<-ctx.Done()
			_ = rs.Close()
		}()
		if err := rs.Serve(); err != nil && !errors.Is(err, io.EOF) {
			s.log.Debug("SFTP session ended", "tenant", tenantID, "error", err)
		}
		_ = rs.Close()
		h.abortAll()
	}
}

type handler struct {
	ctx     context.Context
	tenant  string
	tenants *tenant.Registry
	store   *store.Store
	maxOpen int

	mu   sync.Mutex
	open map[string]*upload
}

// upload adapts a store handle to pkg/sftp and tracks it for SETSTAT and
// session teardown.
type upload struct {
	*store.UploadHandle
	h    *handler
	name string
	once sync.Once
}

func (u *upload) Close() error {
	var err error
	u.once.Do(func() {
		u.h.forget(u)
		err = mapError(u.UploadHandle.Close())
	})
	return err
}

func (u *upload) TransferError(err error) { u.UploadHandle.TransferError(err) }

func (h *handler) forget(u *upload) {
	h.mu.Lock()
	if h.open[u.name] == u {
		delete(h.open, u.name)
	}
	h.mu.Unlock()
}

// abortAll closes uploads the client never closed, keeping them resumable.
func (h *handler) abortAll() {
	h.mu.Lock()
	list := make([]*upload, 0, len(h.open))
	for _, u := range h.open {
		list = append(list, u)
	}
	h.mu.Unlock()
	for _, u := range list {
		u.TransferError(errors.New("SFTP session ended before the file was closed"))
		_ = u.Close()
	}
}

func (h *handler) active() error {
	if !h.tenants.Load().Active(h.tenant) {
		return sftp.ErrSSHFxPermissionDenied
	}
	return nil
}

// mapError turns store errors into errors pkg/sftp reports with the right
// status code and a message the client can show.
func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, store.ErrDraining), errors.Is(err, store.ErrUploadBlocked), errors.Is(err, capacity.ErrCriticalCapacity), errors.Is(err, store.ErrQuota), errors.Is(err, capacity.ErrTooManyUploads):
		return fmt.Errorf("%s (retry later)", err.Error())
	}
	return err
}

func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if err := h.active(); err != nil {
		return nil, err
	}
	f, _, err := h.store.OpenCurrent(h.tenant, r.Filepath)
	if err != nil {
		return nil, mapError(err)
	}
	return f, nil
}

func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if err := h.active(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	full := len(h.open) >= h.maxOpen
	h.mu.Unlock()
	if full {
		return nil, fmt.Errorf("too many open files in this session (limit %d)", h.maxOpen)
	}
	flags := r.Pflags()
	mode := store.ModeTruncate
	switch {
	case flags.Append:
		mode = store.ModeAppend
	case flags.Trunc:
		mode = store.ModeTruncate
	case flags.Excl:
		if _, err := h.store.Stat(h.tenant, r.Filepath); err == nil {
			return nil, os.ErrExist
		}
	default:
		mode = store.ModeResume
	}
	uh, err := h.store.OpenUpload(h.ctx, h.tenant, r.Filepath, "sftp", mode)
	if err != nil {
		return nil, mapError(err)
	}
	name, _ := store.CleanPath(r.Filepath)
	u := &upload{UploadHandle: uh, h: h, name: name}
	h.mu.Lock()
	h.open[name] = u
	h.mu.Unlock()
	return u, nil
}

func (h *handler) Filecmd(r *sftp.Request) error {
	if err := h.active(); err != nil {
		return err
	}
	switch r.Method {
	case "Rename":
		return mapError(h.store.RenameWith(h.tenant, r.Filepath, r.Target, false))
	case "PosixRename":
		return mapError(h.store.RenameWith(h.tenant, r.Filepath, r.Target, true))
	case "Remove":
		return mapError(h.store.Remove(h.tenant, r.Filepath))
	case "Mkdir":
		return mapError(h.store.Mkdir(h.tenant, r.Filepath))
	case "Rmdir":
		return mapError(h.store.RemoveDir(h.tenant, r.Filepath))
	case "Setstat":
		return h.setstat(r)
	case "Symlink", "Link":
		return sftp.ErrSSHFxOpUnsupported
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

// setstat applies a size change to a file open in this session (the usual
// ftruncate pattern). Permissions and times are accepted and ignored: the
// server does not keep them. A size change on a file that is not open cannot
// be honoured and is refused rather than silently ignored.
func (h *handler) setstat(r *sftp.Request) error {
	if !r.AttrFlags().Size {
		return nil
	}
	name, err := store.CleanPath(r.Filepath)
	if err != nil {
		return err
	}
	h.mu.Lock()
	u := h.open[name]
	h.mu.Unlock()
	if u == nil {
		return sftp.ErrSSHFxOpUnsupported
	}
	return mapError(u.Truncate(int64(r.Attributes().Size)))
}

func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if err := h.active(); err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		entries, err := h.store.List(h.tenant, r.Filepath)
		if err != nil {
			return nil, mapError(err)
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			infos = append(infos, entryInfo(e))
		}
		return lister(infos), nil
	case "Stat", "Lstat":
		info, err := h.store.Stat(h.tenant, r.Filepath)
		if err != nil {
			return nil, mapError(err)
		}
		name := path.Base("/" + info.Path)
		if info.Directory {
			return lister([]os.FileInfo{fileInfo{name: name, dir: true, mode: os.ModeDir | 0o750, mod: info.ModTime}}), nil
		}
		return lister([]os.FileInfo{fileInfo{name: name, size: info.Size, mode: 0o640, mod: info.ModTime}}), nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

func entryInfo(e store.ListedEntry) os.FileInfo {
	if e.Directory {
		return fileInfo{name: path.Base(e.Path), dir: true, mode: os.ModeDir | 0o750, mod: time.Now()}
	}
	return fileInfo{name: path.Base(e.Path), size: e.Object.Size, mode: 0o640, mod: e.Object.CreatedAt}
}

type lister []os.FileInfo

func (l lister) ListAt(dst []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

type fileInfo struct {
	name string
	size int64
	mode os.FileMode
	mod  time.Time
	dir  bool
}

func (f fileInfo) Name() string       { return f.name }
func (f fileInfo) Size() int64        { return f.size }
func (f fileInfo) Mode() os.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return f.mod }
func (f fileInfo) IsDir() bool        { return f.dir }
func (f fileInfo) Sys() any           { return nil }
