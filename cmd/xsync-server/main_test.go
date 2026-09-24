package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/bundle"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/platform"
	"gopkg.in/yaml.v3"
)

func setup(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	configPath := filepath.Join(dir, "config.yaml")
	if err := initCommand([]string{"--config", configPath, "--data-dir", data, "--advertise-ip", "127.0.0.1", "--require-mount=false"}); err != nil {
		t.Fatal(err)
	}
	return dir, configPath
}

func readBundle(t *testing.T, name string) bundle.Document {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var doc bundle.Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestAccountAddKeepsOnlyHashesAndEncryptedSecrets(t *testing.T) {
	dir, configPath := setup(t)
	raw, _ := os.ReadFile(configPath)
	if strings.Contains(string(raw), "tenants:") || !strings.Contains(string(raw), "accounts_file:") {
		t.Fatalf("public config:\n%s", raw)
	}
	if err := accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err != nil {
		t.Fatal(err)
	}
	accounts, _ := os.ReadFile(filepath.Join(dir, "accounts.yaml"))
	for _, forbidden := range []string{"sftp_password:", "ftp_password:"} {
		if strings.Contains(string(accounts), forbidden) {
			t.Fatalf("accounts file stores a plaintext password (%s):\n%s", forbidden, accounts)
		}
	}
	if !strings.Contains(string(accounts), "enc:v1:") {
		t.Fatalf("S3 secret not encrypted at rest:\n%s", accounts)
	}
	doc := readBundle(t, filepath.Join(dir, "client-configs", "customer-b.yaml"))
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	acct := cfg.Tenants[0]
	if !config.VerifySecret(doc.SFTP.Password, acct.SFTPPasswordHash, acct.SFTPPassword) || !config.VerifySecret(doc.FTPS.Password, acct.FTPPasswordHash, acct.FTPPassword) {
		t.Fatal("bundle passwords do not verify against the stored hashes")
	}
	if acct.S3SecretKey != doc.S3.SecretKey {
		t.Fatal("decrypted S3 secret does not match the bundle")
	}
	sum := sha256.Sum256([]byte(doc.Download.APIKey))
	if acct.APIKeySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("API key digest mismatch")
	}
	info, _ := os.Stat(filepath.Join(dir, "client-configs", "customer-b.yaml"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode %v", info.Mode().Perm())
	}
	if err = accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err == nil {
		t.Fatal("duplicate account accepted")
	}
	if err = accountAddCommand([]string{"--config", configPath, "--id", "../evil"}); err == nil {
		t.Fatal("path-like account ID accepted")
	}
}

// init --force used to replace the account store with an empty list.
func TestInitForceKeepsAccountsAndKeys(t *testing.T) {
	dir, configPath := setup(t)
	if err := accountAddCommand([]string{"--config", configPath, "--id", "keep-me"}); err != nil {
		t.Fatal(err)
	}
	caBefore, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	sshBefore, _ := os.ReadFile(filepath.Join(dir, "ssh_host_ed25519_key"))
	if err := initCommand([]string{"--config", configPath, "--data-dir", filepath.Join(dir, "data"), "--advertise-ip", "127.0.0.2", "--require-mount=false", "--force"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "keep-me" {
		t.Fatalf("accounts after init --force: %+v", cfg.Tenants)
	}
	caAfter, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	sshAfter, _ := os.ReadFile(filepath.Join(dir, "ssh_host_ed25519_key"))
	if string(caBefore) != string(caAfter) || string(sshBefore) != string(sshAfter) {
		t.Fatal("init --force regenerated keys that bundles depend on")
	}
	if cfg.PublicHost != "127.0.0.2" {
		t.Fatalf("public host = %s", cfg.PublicHost)
	}
}

func TestCertificatesAreCAPlusShortLeafAndRenewKeepsBundlesValid(t *testing.T) {
	dir, configPath := setup(t)
	if err := accountAddCommand([]string{"--config", configPath, "--id", "acct"}); err != nil {
		t.Fatal(err)
	}
	doc := readBundle(t, filepath.Join(dir, "client-configs", "acct.yaml"))
	leaf, err := readCert(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.PublicKeyAlgorithm != x509.ECDSA || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("serving certificate: isCA=%v alg=%v ips=%v", leaf.IsCA, leaf.PublicKeyAlgorithm, leaf.IPAddresses)
	}
	if time.Until(leaf.NotAfter) > 400*24*time.Hour {
		t.Fatalf("serving certificate too long-lived: %v", leaf.NotAfter)
	}
	verify := func() {
		t.Helper()
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(doc.Security.TLSCAPEM)) {
			t.Fatal("bundle has no CA")
		}
		c, _ := readCert(filepath.Join(dir, "tls.crt"))
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			t.Fatalf("bundle CA does not validate the serving certificate: %v", err)
		}
	}
	verify()
	if err := certRenewCommand([]string{"--config", configPath, "--days", "30"}); err != nil {
		t.Fatal(err)
	}
	renewed, _ := readCert(filepath.Join(dir, "tls.crt"))
	if renewed.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Fatal("certificate not renewed")
	}
	verify()
}

func TestAccountLifecycleCommands(t *testing.T) {
	dir, configPath := setup(t)
	if err := accountAddCommand([]string{"--config", configPath, "--id", "acct", "--max-concurrent", "3"}); err != nil {
		t.Fatal(err)
	}
	load := func() config.Tenant {
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Tenants[0]
	}
	if err := accountUpdateCommand([]string{"--config", configPath, "--id", "acct", "--overwrite", "keep", "--max-stored-bytes", "1000"}); err != nil {
		t.Fatal(err)
	}
	if a := load(); a.Overwrite != "keep" || a.MaxStoredBytes != 1000 || a.MaxConcurrent != 3 {
		t.Fatalf("update changed the wrong fields: %+v", a)
	}
	if err := accountSetDisabled([]string{"--config", configPath, "--id", "acct"}, true); err != nil {
		t.Fatal(err)
	}
	if !load().Disabled {
		t.Fatal("account not disabled")
	}
	before := load()
	if err := accountRotateCommand([]string{"--config", configPath, "--id", "acct"}); err != nil {
		t.Fatal(err)
	}
	after := load()
	doc := readBundle(t, filepath.Join(dir, "client-configs", "acct.yaml"))
	if after.APIKeySHA256 == before.APIKeySHA256 || !config.VerifySecret(doc.SFTP.Password, after.SFTPPasswordHash, "") {
		t.Fatal("rotate did not replace credentials consistently")
	}
	if err := accountRemoveCommand([]string{"--config", configPath, "--id", "acct"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(configPath)
	if len(cfg.Tenants) != 0 {
		t.Fatal("account not removed")
	}
}

func legacyCert(t *testing.T, certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xsync"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
}

// A configuration written by the first release (tenants inline, plaintext
// passwords, self-signed certificate) must keep working and migrate.
func TestLegacyConfigMigratesOnFirstAccountChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "legacy.yaml")
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.FTP.PublicHost, cfg.PublicHost = "127.0.0.1", "127.0.0.1"
	cfg.TLS.CertFile, cfg.TLS.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	cfg.SFTP.HostKeyFile = filepath.Join(dir, "ssh_host_ed25519_key")
	legacyCert(t, cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err := generateSSHKey(cfg.SFTP.HostKeyFile); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("legacy-api-key"))
	legacy := config.Tenant{ID: "initial", Weight: 1, APIKeySHA256: hex.EncodeToString(sum[:]), SFTPUser: "initial", SFTPPassword: "legacy-sftp-password", FTPUser: "initial", FTPPassword: "legacy-ftp-password", S3Bucket: "initial", S3AccessKey: "LEGACYKEY", S3SecretKey: "legacy-s3-secret-key", MaxConcurrent: 8}
	cfg.Tenants = []config.Tenant{legacy}
	raw, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tenants) != 2 {
		t.Fatalf("accounts = %d", len(loaded.Tenants))
	}
	if !config.VerifySecret("legacy-sftp-password", loaded.Tenants[0].SFTPPasswordHash, loaded.Tenants[0].SFTPPassword) {
		t.Fatal("legacy password no longer verifies after migration")
	}
	if err := certRenewCommand([]string{"--config", configPath}); err == nil {
		t.Fatal("renew without a CA should explain the --new-ca migration")
	}
	if err := certRenewCommand([]string{"--config", configPath, "--new-ca"}); err != nil {
		t.Fatal(err)
	}
	if loaded, err = config.Load(configPath); err != nil || loaded.TLS.CACertFile == "" {
		t.Fatalf("CA not recorded: %v", err)
	}
}

func TestInitMarksDataVolume(t *testing.T) {
	dir, configPath := setup(t)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataVolumeID == "" {
		t.Fatal("no data volume ID recorded")
	}
	if _, err := platform.CheckDataDir(cfg.DataDir, false, cfg.DataVolumeID, 0); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "unmounted")
	_ = os.MkdirAll(empty, 0o750)
	if _, err := platform.CheckDataDir(empty, false, cfg.DataVolumeID, 0); err == nil {
		t.Fatal("an unmarked directory was accepted as the data volume")
	}
}

// A relative --config used to produce paths that were resolved twice, so the
// accounts file and secrets key landed in (or were looked up in) the wrong
// directory.
func TestInitWithRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := initCommand([]string{"--config", "etc/config.yaml", "--data-dir", "data", "--advertise-ip", "127.0.0.1", "--require-mount=false"}); err != nil {
		t.Fatal(err)
	}
	if err := accountAddCommand([]string{"--config", "etc/config.yaml", "--id", "rel"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "etc", "accounts.yaml"))
	if err != nil {
		t.Fatalf("accounts file not beside the config: %v", err)
	}
	if !strings.Contains(string(raw), "enc:v1:") {
		t.Fatal("S3 secret not encrypted: the secrets key was not found")
	}
}
