package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/sftp"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/platform"
	"github.com/xylandev/xsync/internal/store"
	"golang.org/x/crypto/ssh"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return cert, keyFile
}

func writeHostKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	name := filepath.Join(dir, "host")
	_ = os.WriteFile(name, pem.EncodeToMemory(block), 0o600)
	return name
}

type account struct {
	config.Tenant
	apiKey, password string
}

func newAccount(t *testing.T, id string) account {
	t.Helper()
	apiKey, password := id+"-api-key-0123456789", id+"-password-0123"
	sum := sha256.Sum256([]byte(apiKey))
	hash, err := config.HashSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	return account{Tenant: config.Tenant{ID: id, APIKeySHA256: hex.EncodeToString(sum[:]), SFTPUser: id, SFTPPasswordHash: hash, FTPUser: id, FTPPasswordHash: hash, S3Bucket: id + "-bucket", S3AccessKey: strings.ToUpper(id) + "KEY", S3SecretKey: id + "-s3-secret-0123", MaxConcurrent: 4}, apiKey: apiKey, password: password}
}

type harness struct {
	t          *testing.T
	cfg        config.Config
	configPath string
	cancel     context.CancelFunc
	done       chan error
	http       *http.Client
}

func startServer(t *testing.T, accounts ...account) *harness {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	_ = os.MkdirAll(data, 0o750)
	if err := platform.WriteVolumeMarker(data, "test-volume"); err != nil {
		t.Fatal(err)
	}
	cert, key := writeCert(t, dir)
	cfg := config.Default()
	cfg.DataDir, cfg.RequireMount, cfg.DataVolumeID = data, false, "test-volume"
	cfg.PublicHost = "127.0.0.1"
	cfg.FTP.PublicHost = "127.0.0.1"
	cfg.TLS = config.TLSConfig{CertFile: cert, KeyFile: key}
	cfg.SFTP.HostKeyFile = writeHostKey(t, dir)
	cfg.Download.Listen, cfg.SFTP.Listen, cfg.FTP.Listen, cfg.S3.Listen, cfg.Metrics.Listen = freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t)
	_, p, _ := net.SplitHostPort(freeAddr(t))
	port, _ := strconv.Atoi(p)
	cfg.FTP.PassiveStart, cfg.FTP.PassiveEnd = port, port
	cfg.Capacity.MinFreeBytes = 0
	cfg.ShutdownGrace = 5 * time.Second
	cfg.AccountsFile = filepath.Join(dir, "accounts.yaml")
	cfg.AdminTokenFile = filepath.Join(dir, "admin.token")
	_ = os.WriteFile(cfg.AdminTokenFile, []byte("admin-secret\n"), 0o600)
	for _, a := range accounts {
		cfg.Tenants = append(cfg.Tenants, a.Tenant)
	}
	if cfg.Tenants == nil {
		cfg.Tenants = []config.Tenant{}
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := config.Write(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, cfg: loaded, configPath: configPath, cancel: cancel, done: make(chan error, 1),
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { h.done <- RunWithOptions(ctx, loaded, log, Options{Version: "test"}) }()
	t.Cleanup(func() { h.stop() })
	h.waitFor(loaded.Download.Listen)
	h.waitFor(loaded.SFTP.Listen)
	h.waitFor(loaded.S3.Listen)
	h.waitFor(loaded.Metrics.Listen)
	return h
}

func (h *harness) waitFor(addr string) {
	h.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
	}
	h.t.Fatalf("%s never started listening", addr)
}

func (h *harness) stop() error {
	if h.cancel == nil {
		return nil
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.done:
		return err
	case <-time.After(20 * time.Second):
		h.t.Fatal("server did not stop")
		return nil
	}
}

func (h *harness) sftp(a account) *sftp.Client {
	h.t.Helper()
	conn, err := ssh.Dial("tcp", h.cfg.SFTP.Listen, &ssh.ClientConfig{User: a.SFTPUser, Auth: []ssh.AuthMethod{ssh.Password(a.password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close(); conn.Close() })
	return c
}

func (h *harness) api(a account, method, path, body string, headers ...string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(method, "https://"+h.cfg.Download.Listen+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// download claims, fetches and commits one object, returning its path and
// content.
func (h *harness) download(a account) (string, string) {
	h.t.Helper()
	resp := h.api(a, http.MethodPost, "/v1/claims", `{"client_id":"it","wait_seconds":5}`)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		h.t.Fatalf("claim status %d", resp.StatusCode)
	}
	var claim model.Claim
	_ = json.NewDecoder(resp.Body).Decode(&claim)
	resp.Body.Close()
	resp = h.api(a, http.MethodGet, "/v1/objects/"+claim.ObjectID+"/content", "", "X-Xsync-Lease-ID", claim.LeaseID)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sum := sha256.Sum256(raw)
	commit, _ := json.Marshal(map[string]any{"lease_id": claim.LeaseID, "sha256": hex.EncodeToString(sum[:]), "size": len(raw)})
	resp = h.api(a, http.MethodPost, "/v1/objects/"+claim.ObjectID+"/commit", string(commit))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		h.t.Fatalf("commit status %d", resp.StatusCode)
	}
	return claim.Path, string(raw)
}

func TestEndToEndAcrossProtocols(t *testing.T) {
	alice := newAccount(t, "alice")
	h := startServer(t, alice)

	c := h.sftp(alice)
	f, err := c.Create("/in/report.csv.filepart")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("a,b,c\n"))
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.PosixRename("/in/report.csv.filepart", "/in/report.csv"); err != nil {
		t.Fatal(err)
	}
	if p, body := h.download(alice); p != "in/report.csv" || body != "a,b,c\n" {
		t.Fatalf("downloaded %s %q", p, body)
	}

	s3c := awss3.New(awss3.Options{BaseEndpoint: aws.String("https://" + h.cfg.S3.Listen), Region: "us-east-1", UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(alice.S3AccessKey, alice.S3SecretKey, ""), HTTPClient: h.http})
	if _, err = s3c.PutObject(context.Background(), &awss3.PutObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("s3/obj.bin"), Body: bytes.NewReader([]byte("from s3"))}); err != nil {
		t.Fatal(err)
	}
	if p, body := h.download(alice); p != "s3/obj.bin" || body != "from s3" {
		t.Fatalf("downloaded %s %q", p, body)
	}
}

func TestAccountsReloadWithoutRestart(t *testing.T) {
	alice := newAccount(t, "alice")
	h := startServer(t, alice)
	bob := newAccount(t, "bob")
	if err := config.AddTenant(h.configPath, bob.Tenant); err != nil {
		t.Fatal(err)
	}
	// The watcher polls every 5 seconds; the admin API reloads at once.
	req, _ := http.NewRequest(http.MethodPost, "http://"+h.cfg.Metrics.Listen+"/admin/reload", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reload = %v %v", resp, err)
	}
	resp.Body.Close()
	c := h.sftp(bob)
	if err := c.Mkdir("/works"); err != nil {
		t.Fatal(err)
	}
	// Disabling takes effect on the next request.
	if err := config.UpdateAccounts(h.configPath, func(ts []config.Tenant) ([]config.Tenant, error) {
		for i := range ts {
			if ts[i].ID == "bob" {
				ts[i].Disabled = true
			}
		}
		return ts, nil
	}); err != nil {
		t.Fatal(err)
	}
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	r := h.api(bob, http.MethodPost, "/v1/claims", `{"client_id":"x"}`)
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled account still authenticates: %d", r.StatusCode)
	}
}

func TestOpsEndpoints(t *testing.T) {
	alice := newAccount(t, "alice")
	h := startServer(t, alice)
	resp, err := http.Get("http://" + h.cfg.Metrics.Listen + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"# TYPE xsync_ready_objects gauge", `xsync_tenant_oldest_ready_age_seconds{tenant="alice"}`, "xsync_upload_limit_bytes_per_second +Inf", "xsync_tls_cert_not_after_seconds"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	resp, _ = http.Get("http://" + h.cfg.Metrics.Listen + "/admin/tenants")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin API without token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+h.cfg.Metrics.Listen+"/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tenants struct {
		Tenants []struct {
			ID     string `json:"id"`
			Upload struct {
				Limit *float64 `json:"limit_bytes_per_second"`
			} `json:"upload"`
		} `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tenants); err != nil || len(tenants.Tenants) != 1 || tenants.Tenants[0].Upload.Limit != nil {
		t.Fatalf("admin tenants = %+v, %v", tenants, err)
	}
	resp.Body.Close()
	resp, _ = http.Get("http://" + h.cfg.Metrics.Listen + "/healthz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
}

// SIGTERM used to close the store within a millisecond and cut every
// transfer. Uploads in flight must be able to finish during the grace period.
func TestGracefulShutdownLetsUploadsFinish(t *testing.T) {
	alice := newAccount(t, "alice")
	h := startServer(t, alice)
	c := h.sftp(alice)
	f, err := c.Create("/late.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("first half ")); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- h.stop() }()
	time.Sleep(300 * time.Millisecond)
	if _, err = f.Write([]byte("second half")); err != nil {
		t.Fatalf("write during drain: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close during drain: %v", err)
	}
	if err = <-stopped; err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(h.cfg.DataDir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o, err := st.Current("alice", "late.bin")
	if err != nil || o.Size != int64(len("first half second half")) {
		t.Fatalf("upload finished during drain was lost: %+v %v", o, err)
	}
}
