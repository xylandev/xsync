package sftpadapter

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	cfg      config.SFTPConfig
	tenants  []config.Tenant
	store    *store.Store
	log      *slog.Logger
	listener net.Listener
}

func New(cfg config.SFTPConfig, tenants []config.Tenant, st *store.Store, log *slog.Logger) *Server {
	return &Server{cfg: cfg, tenants: tenants, store: st, log: log}
}

func (s *Server) Serve(ctx context.Context) error {
	hostKey, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return fmt.Errorf("read SFTP host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return fmt.Errorf("parse SFTP host key: %w", err)
	}
	sshCfg := &ssh.ServerConfig{}
	sshCfg.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		for _, t := range s.tenants {
			if t.SFTPUser == meta.User() && subtle.ConstantTimeCompare([]byte(t.SFTPPassword), password) == 1 {
				return &ssh.Permissions{Extensions: map[string]string{"tenant": t.ID}}, nil
			}
		}
		return nil, errors.New("authentication failed")
	}
	sshCfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		for _, t := range s.tenants {
			if t.SFTPUser != meta.User() {
				continue
			}
			for _, raw := range t.AuthorizedKeys {
				authorized, _, _, _, e := ssh.ParseAuthorizedKey([]byte(raw))
				if e == nil && bytes.Equal(authorized.Marshal(), key.Marshal()) {
					return &ssh.Permissions{Extensions: map[string]string{"tenant": t.ID}}, nil
				}
			}
		}
		return nil, errors.New("authentication failed")
	}
	sshCfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.listener = ln
	go func() { <-ctx.Done(); _ = ln.Close() }()
	s.log.Info("SFTP listening", "addr", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("SFTP accept", "error", err)
			continue
		}
		go s.handle(conn, sshCfg)
	}
}

func (s *Server) handle(raw net.Conn, cfg *ssh.ServerConfig) {
	defer raw.Close()
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		s.log.Warn("SFTP handshake", "error", err)
		return
	}
	defer conn.Close()
	tenant := ""
	if conn.Permissions != nil {
		tenant = conn.Permissions.Extensions["tenant"]
	}
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
				ok := req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if ok && !accepted {
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
		h := &handler{tenant: tenant, store: s.store}
		rs := sftp.NewRequestServer(channel, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}, sftp.WithRSAllocator(), sftp.WithRSMaxTxPacket(1<<20))
		if err := rs.Serve(); err != nil && !errors.Is(err, io.EOF) {
			s.log.Warn("SFTP session", "tenant", tenant, "error", err)
		}
		_ = rs.Close()
	}
}

type handler struct {
	tenant string
	store  *store.Store
}

func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, _, err := h.store.OpenCurrent(h.tenant, r.Filepath)
	return f, err
}
func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	flags := r.Pflags()
	if flags.Append || (!flags.Trunc && !flags.Excl) {
		return h.store.BeginUploadFromCurrent(r.Context(), h.tenant, r.Filepath, "sftp")
	}
	return h.store.BeginUpload(r.Context(), h.tenant, r.Filepath, "sftp")
}
func (h *handler) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Rename", "PosixRename":
		return h.store.Rename(h.tenant, r.Filepath, r.Target)
	case "Remove":
		return h.store.Remove(h.tenant, r.Filepath)
	case "Mkdir":
		return h.store.Mkdir(h.tenant, r.Filepath)
	case "Rmdir":
		return h.store.RemoveDir(h.tenant, r.Filepath)
	case "Setstat":
		return nil
	case "Symlink", "Link":
		return errors.New("links are disabled")
	default:
		return errors.New("unsupported operation")
	}
}

func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		entries, err := h.store.List(h.tenant, r.Filepath)
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			infos = append(infos, entryInfo(e))
		}
		return lister(infos), nil
	case "Stat", "Lstat":
		clean := strings.TrimPrefix(path.Clean(r.Filepath), "/")
		if clean == "." || clean == "" {
			return lister([]os.FileInfo{fileInfo{name: "/", dir: true, mode: os.ModeDir | 0o750, mod: time.Now()}}), nil
		}
		o, err := h.store.Current(h.tenant, clean)
		if err == nil {
			return lister([]os.FileInfo{fileInfo{name: path.Base(clean), size: o.Size, mode: 0o640, mod: o.CreatedAt}}), nil
		}
		exists, listErr := h.store.DirectoryExists(h.tenant, clean)
		if listErr == nil && exists {
			return lister([]os.FileInfo{fileInfo{name: path.Base(clean), dir: true, mode: os.ModeDir | 0o750, mod: time.Now()}}), nil
		}
		return nil, err
	default:
		return nil, errors.New("unsupported list operation")
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
	if int(off)+n >= len(l) {
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
