package ftpadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secsy/goftp"
	"github.com/xylandev/xsync/internal/certstore"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

func freePort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), port
}

func tlsFiles(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type env struct {
	st   *store.Store
	srv  *Server
	addr string
}

func start(t *testing.T, tenants []config.Tenant, grace time.Duration) *env {
	t.Helper()
	st, err := store.Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	addr, _ := freePort(t)
	_, passive := freePort(t)
	cert, key := tlsFiles(t)
	certs, err := certstore.New(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := New(config.FTPConfig{Enabled: true, Listen: addr, PublicHost: "127.0.0.1", PassiveStart: passive, PassiveEnd: passive, CloseGrace: grace}, tenant.NewRegistry(tenants), st, Options{Limits: config.Default().Limits, Certs: certs}, nil)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		srv.Abort()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("FTP server did not stop")
		}
	})
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if probe, e := net.DialTimeout("tcp", addr, 100*time.Millisecond); e == nil {
			probe.Close()
			break
		}
	}
	return &env{st: st, srv: srv, addr: addr}
}

func plainTenant() []config.Tenant {
	return []config.Tenant{{ID: "tenant", FTPUser: "user", FTPPassword: "pass-word-123", AllowPlainFTP: true}}
}

func TestFTPProtocolRoundTrip(t *testing.T) {
	e := start(t, plainTenant(), 0)
	client, err := goftp.DialConfig(goftp.Config{User: "user", Password: "pass-word-123", Timeout: 2 * time.Second}, e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Store("hello.txt", bytes.NewBufferString("hello ftp")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = client.Retrieve("hello.txt", &out); err != nil || out.String() != "hello ftp" {
		t.Fatalf("got %q, %v", out.String(), err)
	}
	if err = client.Rename("hello.txt", "renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err = client.Delete("renamed.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestFTPSProtocolRoundTrip(t *testing.T) {
	e := start(t, []config.Tenant{{ID: "tenant", FTPUser: "user", FTPPassword: "pass-word-123"}}, 0)
	client, err := goftp.DialConfig(goftp.Config{User: "user", Password: "pass-word-123", Timeout: 2 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}, TLSMode: goftp.TLSExplicit}, e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Store("secure.txt", bytes.NewBufferString("secure")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = client.Retrieve("secure.txt", &out); err != nil || out.String() != "secure" {
		t.Fatalf("got %q, %v", out.String(), err)
	}
}

func TestFTPRequiresTLSUnlessAllowed(t *testing.T) {
	e := start(t, []config.Tenant{{ID: "tenant", FTPUser: "user", FTPPassword: "pass-word-123"}}, 0)
	if _, err := goftp.DialConfig(goftp.Config{User: "user", Password: "pass-word-123", Timeout: 2 * time.Second}, e.addr); err == nil {
		c, _ := goftp.DialConfig(goftp.Config{User: "user", Password: "pass-word-123", Timeout: 2 * time.Second}, e.addr)
		if err := c.Store("x", bytes.NewBufferString("x")); err == nil {
			t.Fatal("plain FTP upload accepted for an account that requires TLS")
		}
	}
}

// rawFTP drives the control connection directly, for commands goftp lacks.
type rawFTP struct {
	t    *testing.T
	conn *textproto.Conn
}

func dialRaw(t *testing.T, addr string) *rawFTP {
	t.Helper()
	c, err := textproto.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	r := &rawFTP{t: t, conn: c}
	r.expect(220)
	r.cmd(331, "USER user")
	r.cmd(230, "PASS pass-word-123")
	r.cmd(200, "TYPE I")
	return r
}

func (r *rawFTP) expect(code int) string {
	r.t.Helper()
	_, msg, err := r.conn.ReadResponse(code)
	if err != nil {
		r.t.Fatalf("expected %d: %v", code, err)
	}
	return msg
}

func (r *rawFTP) cmd(code int, format string, args ...any) string {
	r.t.Helper()
	if _, err := r.conn.Cmd(format, args...); err != nil {
		r.t.Fatal(err)
	}
	return r.expect(code)
}

func (r *rawFTP) pasv() net.Conn {
	r.t.Helper()
	msg := r.cmd(227, "PASV")
	open, closeIdx := strings.IndexByte(msg, '('), strings.IndexByte(msg, ')')
	parts := strings.Split(msg[open+1:closeIdx], ",")
	hi, _ := strconv.Atoi(parts[4])
	lo, _ := strconv.Atoi(parts[5])
	data, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", hi*256+lo))
	if err != nil {
		r.t.Fatal(err)
	}
	return data
}

// upload sends data with the given command and returns the final reply code.
func (r *rawFTP) upload(command, data string) int {
	r.t.Helper()
	conn := r.pasv()
	if _, err := r.conn.Cmd("%s", command); err != nil {
		r.t.Fatal(err)
	}
	r.expect(150)
	_, _ = io.WriteString(conn, data)
	conn.Close()
	code, _, _ := r.conn.ReadResponse(0)
	return code
}

// APPE used to write from offset 0 over the existing content.
func TestFTPAppendAndRestResume(t *testing.T) {
	e := start(t, plainTenant(), 0)
	r := dialRaw(t, e.addr)
	if code := r.upload("STOR log.txt", "AAAAAAAAAA"); code != 226 {
		t.Fatalf("STOR = %d", code)
	}
	if code := r.upload("APPE log.txt", "BBB"); code != 226 {
		t.Fatalf("APPE = %d", code)
	}
	var out bytes.Buffer
	f, _, err := e.st.OpenCurrent("tenant", "log.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(&out, f)
	f.Close()
	if out.String() != "AAAAAAAAAABBB" {
		t.Fatalf("APPE produced %q", out.String())
	}

	// REST + STOR continues from the size SIZE reported.
	size := r.cmd(213, "SIZE log.txt")
	if size != "13" {
		t.Fatalf("SIZE = %q", size)
	}
	r.cmd(350, "REST 13")
	if code := r.upload("STOR log.txt", "CC"); code != 226 {
		t.Fatalf("REST STOR = %d", code)
	}
	out.Reset()
	f, _, _ = e.st.OpenCurrent("tenant", "log.txt")
	_, _ = io.Copy(&out, f)
	f.Close()
	if out.String() != "AAAAAAAAAABBBCC" {
		t.Fatalf("resume produced %q", out.String())
	}
	r.cmd(221, "QUIT")
}

// A client that dies mid-transfer closes the data connection and then the
// control connection. That must not publish the truncated file.
func TestFTPTruncatedTransferIsNotPublished(t *testing.T) {
	e := start(t, plainTenant(), 300*time.Millisecond)
	r := dialRaw(t, e.addr)
	conn := r.pasv()
	if _, err := r.conn.Cmd("STOR partial.bin"); err != nil {
		t.Fatal(err)
	}
	r.expect(150)
	_, _ = io.WriteString(conn, "first half")
	conn.Close()
	r.conn.Close() // control connection drops right after
	time.Sleep(time.Second)
	if _, err := e.st.Current("tenant", "partial.bin"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("truncated FTP upload was published: %v", err)
	}
	if info, err := e.st.Stat("tenant", "partial.bin"); err != nil || !info.Partial {
		t.Fatalf("truncated upload not kept for resumption: %+v %v", info, err)
	}
}

func TestFTPAlloMismatchIsNotPublished(t *testing.T) {
	e := start(t, plainTenant(), 0)
	r := dialRaw(t, e.addr)
	r.cmd(200, "ALLO 100")
	if code := r.upload("STOR short.bin", "only ten b"); code == 226 {
		t.Fatal("upload shorter than ALLO was accepted")
	}
	if _, err := e.st.Current("tenant", "short.bin"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("short upload published: %v", err)
	}
}
