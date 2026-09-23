package sftpadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
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

func TestSFTPProtocolRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	addr := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := New(config.SFTPConfig{Enabled: true, Listen: addr, HostKeyFile: hostKey(t)}, []config.Tenant{{ID: "tenant", SFTPUser: "user", SFTPPassword: "pass"}}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	sshCfg := &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.Password("pass")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}
	var conn *ssh.Client
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		conn, err = ssh.Dial("tcp", addr, sshCfg)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	file, err := client.Create("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	readFile, err := client.Open("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(readFile)
	_ = readFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "hello" {
		t.Fatalf("got %q", raw)
	}
	if err = client.Rename("/hello.txt", "/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if err = client.Remove("/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	client.Close()
	conn.Close()
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal(fmt.Errorf("SFTP server did not stop"))
	}
}
