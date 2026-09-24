package sftpadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/xylandev/xsync/internal/capacity"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
	"golang.org/x/crypto/ssh"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func hostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "host-key")
	if err = os.WriteFile(name, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

type env struct {
	t      *testing.T
	st     *store.Store
	srv    *Server
	addr   string
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, tenants []config.Tenant, gate store.Gate, limits config.LimitsConfig, auth *netguard.AuthLimiter) *env {
	t.Helper()
	st, err := store.Open(t.TempDir(), gate, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	addr := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	srv := New(config.SFTPConfig{Enabled: true, Listen: addr, HostKeyFile: hostKey(t)}, tenant.NewRegistry(tenants), st, Options{Limits: limits, Auth: auth}, nil)
	e := &env{t: t, st: st, srv: srv, addr: addr, cancel: cancel, done: make(chan error, 1)}
	go func() { e.done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		srv.Abort()
		select {
		case <-e.done:
		case <-time.After(3 * time.Second):
			t.Error("SFTP server did not stop")
		}
	})
	return e
}

func (e *env) dial(user, pass string) (*sftp.Client, error) {
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}
	var conn *ssh.Client
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if conn, err = ssh.Dial("tcp", e.addr, cfg); err == nil {
			break
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	e.t.Cleanup(func() { c.Close(); conn.Close() })
	return c, nil
}

func defaultTenant() []config.Tenant {
	return []config.Tenant{{ID: "tenant", SFTPUser: "user", SFTPPassword: "pass-word-123"}}
}

func write(t *testing.T, c *sftp.Client, name string, flags int, data string) error {
	t.Helper()
	f, err := c.OpenFile(name, flags)
	if err != nil {
		return err
	}
	if _, err = f.Write([]byte(data)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func read(t *testing.T, c *sftp.Client, name string) string {
	t.Helper()
	f, err := c.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSFTPProtocolRoundTrip(t *testing.T) {
	e := start(t, defaultTenant(), nil, config.Default().Limits, nil)
	c, err := e.dial("user", "pass-word-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = write(t, c, "/hello.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, "hello"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, c, "/hello.txt"); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if err = c.Rename("/hello.txt", "/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Stat("/hello.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat of renamed file: %v", err)
	}
	if err = c.Remove("/renamed.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestSFTPAppendAndTruncate(t *testing.T) {
	e := start(t, defaultTenant(), nil, config.Default().Limits, nil)
	c, err := e.dial("user", "pass-word-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = write(t, c, "/log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, "AAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if err = write(t, c, "/log", os.O_WRONLY|os.O_APPEND, "BBB"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, c, "/log"); got != "AAAAAAAAAABBB" {
		t.Fatalf("append produced %q", got)
	}
	// Open without O_TRUNC, ftruncate, write shorter content.
	f, err := c.OpenFile("/log", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, c, "/log"); got != "new" {
		t.Fatalf("truncate produced %q", got)
	}
}

func TestSFTPTemporaryNameIsHeldUntilRename(t *testing.T) {
	e := start(t, defaultTenant(), nil, config.Default().Limits, nil)
	c, err := e.dial("user", "pass-word-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = write(t, c, "/data.csv.filepart", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, "rows"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.st.ClaimNext("tenant", "c", "", time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("temporary file delivered: %v", err)
	}
	if err = c.PosixRename("/data.csv.filepart", "/data.csv"); err != nil {
		t.Fatal(err)
	}
	claim, err := e.st.ClaimNext("tenant", "c", "", time.Minute)
	if err != nil || claim.Path != "data.csv" {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
}

// Opening more files than max_concurrent on one session used to park the
// session's only command worker forever and leak the slots.
func TestSFTPTooManyConcurrentUploadsFailsFast(t *testing.T) {
	disk := capacity.New(t.TempDir(), config.CapacityConfig{SoftPercent: 75, HardPercent: 90, CriticalPercent: 95, TargetRunway: time.Minute, UploadSlotWait: 100 * time.Millisecond}, []config.Tenant{{ID: "tenant", MaxConcurrent: 2}})
	e := start(t, defaultTenant(), disk, config.Default().Limits, nil)
	c, err := e.dial("user", "pass-word-123")
	if err != nil {
		t.Fatal(err)
	}
	var open []*sftp.File
	for i := 0; i < 2; i++ {
		f, err := c.OpenFile("/f"+string(rune('a'+i)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, f)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.OpenFile("/third", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("third upload admitted beyond max_concurrent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session deadlocked waiting for a slot")
	}
	for _, f := range open {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err = write(t, c, "/after", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, "x"); err != nil {
		t.Fatalf("slots not returned: %v", err)
	}
}

func TestSFTPSessionLimitAndAbort(t *testing.T) {
	limits := config.Default().Limits
	limits.MaxOpenFilesPerSession = 1
	e := start(t, defaultTenant(), nil, limits, nil)
	c, err := e.dial("user", "pass-word-123")
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.OpenFile("/a", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if _, err = c.OpenFile("/b", os.O_WRONLY|os.O_CREATE|os.O_TRUNC); err == nil {
		t.Fatal("open-file limit not enforced")
	}
	e.srv.Abort()
	// The aborted upload is kept for resumption, not published.
	if _, err = e.st.Current("tenant", "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("aborted upload published: %v", err)
	}
	if info, err := e.st.Stat("tenant", "a"); err != nil || !info.Partial {
		t.Fatalf("aborted upload not resumable: %+v %v", info, err)
	}
}

func TestSFTPAuthThrottleAndDisabledAccount(t *testing.T) {
	tenants := append(defaultTenant(), config.Tenant{ID: "off", SFTPUser: "off", SFTPPassword: "pass-word-123", Disabled: true})
	e := start(t, tenants, nil, config.Default().Limits, netguard.NewAuthLimiter(2))
	if _, err := e.dial("off", "pass-word-123"); err == nil {
		t.Fatal("disabled account authenticated")
	}
	if _, err := e.dial("user", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := e.dial("user", "pass-word-123"); err == nil {
		t.Fatal("throttled address authenticated")
	}
}

func TestSFTPHandshakeTimeout(t *testing.T) {
	limits := config.Default().Limits
	limits.HandshakeTimeout = 200 * time.Millisecond
	e := start(t, defaultTenant(), nil, limits, nil)
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", e.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	for {
		if _, err = conn.Read(buf); err != nil {
			break
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("silent connection was not closed by the handshake timeout")
	}
}
