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
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/secsy/goftp"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
)

func freePort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port
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

func TestFTPProtocolRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	addr, _ := freePort(t)
	_, passive := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := New(config.FTPConfig{Enabled: true, Listen: addr, PublicHost: "127.0.0.1", PassiveStart: passive, PassiveEnd: passive}, config.TLSConfig{}, []config.Tenant{{ID: "tenant", FTPUser: "user", FTPPassword: "pass", AllowPlainFTP: true}}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	var probe net.Conn
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		probe, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			probe.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	client, err := goftp.DialConfig(goftp.Config{User: "user", Password: "pass", Timeout: time.Second}, addr)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Store("hello.txt", bytes.NewBufferString("hello ftp")); err != nil {
		t.Fatalf("control=%s passive=%d: %v", addr, passive, err)
	}
	var out bytes.Buffer
	if err = client.Retrieve("hello.txt", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello ftp" {
		t.Fatalf("got %q", out.String())
	}
	if err = client.Rename("hello.txt", "renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err = client.Delete("renamed.txt"); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FTP server did not stop")
	}
}

func TestFTPSProtocolRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	addr, _ := freePort(t)
	_, passive := freePort(t)
	cert, key := tlsFiles(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := New(config.FTPConfig{Enabled: true, Listen: addr, PublicHost: "127.0.0.1", PassiveStart: passive, PassiveEnd: passive}, config.TLSConfig{CertFile: cert, KeyFile: key}, []config.Tenant{{ID: "tenant", FTPUser: "user", FTPPassword: "pass"}}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		probe, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			probe.Close()
			err = nil
			break
		}
		err = e
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	client, err := goftp.DialConfig(goftp.Config{User: "user", Password: "pass", Timeout: time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}, TLSMode: goftp.TLSExplicit}, addr)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Store("secure.txt", bytes.NewBufferString("secure")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = client.Retrieve("secure.txt", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "secure" {
		t.Fatalf("got %q", out.String())
	}
	_ = client.Close()
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FTPS server did not stop")
	}
}
