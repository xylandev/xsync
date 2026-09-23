package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xylandev/xsync/internal/config"
	"gopkg.in/yaml.v3"
)

type testConnectionBundle struct {
	Version  int    `yaml:"version"`
	Account  string `yaml:"account"`
	Download struct {
		Endpoint string `yaml:"endpoint"`
		APIKey   string `yaml:"api_key"`
	} `yaml:"download"`
	Security struct {
		TLSCAPEM string `yaml:"tls_ca_pem"`
	} `yaml:"security"`
}

func TestAccountAddCreatesAllProtocolCredentials(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := initCommand([]string{"--config", configPath, "--data-dir", dir, "--advertise-ip", "127.0.0.1", "--require-mount=false"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tenants:") || strings.Contains(string(raw), "sftp_password:") {
		t.Fatalf("public config contains managed account secrets:\n%s", raw)
	}
	if !strings.Contains(string(raw), "accounts_file:") {
		t.Fatalf("public config does not reference the account store:\n%s", raw)
	}
	initialized, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(initialized.Tenants) != 0 {
		t.Fatalf("init created %d accounts, want 0", len(initialized.Tenants))
	}
	if _, statErr := os.Stat(filepath.Join(dir, "client-configs")); !os.IsNotExist(statErr) {
		t.Fatalf("init unexpectedly created a client-configs directory: %v", statErr)
	}
	if err := accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants) != 1 {
		t.Fatalf("tenant count = %d, want 1", len(cfg.Tenants))
	}
	account := cfg.Tenants[0]
	if account.ID != "customer-b" || account.APIKeySHA256 == "" || account.SFTPUser == "" || account.SFTPPassword == "" || account.FTPUser == "" || account.FTPPassword == "" || account.S3Bucket == "" || account.S3AccessKey == "" || account.S3SecretKey == "" {
		t.Fatalf("incomplete account credentials: %+v", account)
	}
	bundlePath := filepath.Join(dir, "client-configs", "customer-b.yaml")
	bundleRaw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var connection testConnectionBundle
	if err = yaml.Unmarshal(bundleRaw, &connection); err != nil {
		t.Fatal(err)
	}
	if connection.Version != 1 || connection.Account != "customer-b" || connection.Download.Endpoint != "https://127.0.0.1:9443" || connection.Download.APIKey == "" || !strings.Contains(connection.Security.TLSCAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("incomplete connection bundle: %+v", connection)
	}
	st, statErr := os.Stat(bundlePath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %v; want 0600", st.Mode().Perm())
	}
	if err = accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err == nil {
		t.Fatal("duplicate account was accepted")
	}
}

func TestAccountAddMigratesGeneratedLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "legacy.yaml")
	initial, _, err := newTenant("initial", "initial", 1, 8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.FTP.PublicHost = "127.0.0.1"
	cfg.PublicHost = "127.0.0.1"
	cfg.TLS.CertFile = filepath.Join(dir, "tls.crt")
	cfg.TLS.KeyFile = filepath.Join(dir, "tls.key")
	cfg.SFTP.HostKeyFile = filepath.Join(dir, "ssh_host_ed25519_key")
	if err = generateTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err = generateSSHKey(cfg.SFTP.HostKeyFile); err != nil {
		t.Fatal(err)
	}
	cfg.Tenants = []config.Tenant{initial}
	if err = config.Write(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err = accountAddCommand([]string{"--config", configPath, "--id", "customer-b"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tenants:") || !strings.Contains(string(raw), "accounts_file:") {
		t.Fatalf("legacy config was not simplified:\n%s", raw)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tenants) != 2 {
		t.Fatalf("account count = %d, want 2", len(loaded.Tenants))
	}
}

func TestGenerateTLSUsesECDSA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := generateTLS(certFile, keyFile, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("PublicKeyAlgorithm = %s, want ECDSA for client TLS compatibility", cert.PublicKeyAlgorithm)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP SANs = %v", cert.IPAddresses)
	}
}
