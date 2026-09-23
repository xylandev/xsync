package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xylandev/xsync/internal/app"
	"github.com/xylandev/xsync/internal/bundle"
	"github.com/xylandev/xsync/internal/config"
	"golang.org/x/crypto/ssh"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCommand(os.Args[2:])
	case "validate-config":
		err = validateCommand(os.Args[2:])
	case "serve":
		err = serveCommand(os.Args[2:])
	case "account":
		err = accountCommand(os.Args[2:])
	case "healthcheck":
		err = healthcheckCommand(os.Args[2:])
	case "version":
		fmt.Printf("xsync-server %s (commit %s, built %s)\n", version, commit, buildDate)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsync-server:", err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: xsync-server <init|account add|validate-config|serve|healthcheck|version> [options]")
}

func accountCommand(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: xsync-server account add --id <account> [options]")
	}
	return accountAddCommand(args[1:])
}

func accountAddCommand(args []string) error {
	fs := flag.NewFlagSet("account add", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	id := fs.String("id", "", "account ID and protocol username")
	s3Bucket := fs.String("s3-bucket", "", "S3 bucket name (defaults to account ID)")
	weight := fs.Int("weight", 1, "upload fairness weight")
	maxConcurrent := fs.Int("max-concurrent", 8, "maximum concurrent uploads")
	maxUploadBPS := fs.Int64("max-upload-bps", 0, "per-account upload limit in bytes/s; 0 is unlimited")
	allowPlainFTP := fs.Bool("allow-plain-ftp", false, "allow unencrypted FTP for this account")
	output := fs.String("client-config", "", "connection bundle output (defaults beside config.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("--id is required")
	}
	bucket := *s3Bucket
	if bucket == "" {
		bucket = *id
	}
	if !validS3Bucket(bucket) {
		return fmt.Errorf("invalid S3 bucket %q; use 3-63 lowercase letters, digits, dots or hyphens", bucket)
	}
	tenant, credentials, err := newTenant(*id, bucket, *weight, *maxConcurrent, *maxUploadBPS, *allowPlainFTP)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	bundlePath := *output
	if bundlePath == "" {
		bundlePath = bundle.DefaultPath(*configPath, tenant.ID)
	}
	doc, err := bundle.New(cfg, tenant, bundle.Secrets{APIKey: credentials.apiKey, SFTPPassword: credentials.sftpPassword, FTPPassword: credentials.ftpPassword, S3Secret: credentials.s3Secret})
	if err != nil {
		return err
	}
	if err = bundle.Write(bundlePath, doc, false); err != nil {
		return err
	}
	if err = config.AddTenant(*configPath, tenant); err != nil {
		_ = os.Remove(bundlePath)
		return err
	}
	printCredentials(*configPath, tenant, bundlePath)
	fmt.Println("restart xsync-server for the new account to take effect")
	return nil
}

type accountCredentials struct {
	apiKey, sftpPassword, ftpPassword, s3Secret string
}

func newTenant(id, bucket string, weight, maxConcurrent int, maxUploadBPS int64, allowPlainFTP bool) (config.Tenant, accountCredentials, error) {
	apiKey, err := secret(32)
	if err != nil {
		return config.Tenant{}, accountCredentials{}, err
	}
	sftpPass, err := secret(20)
	if err != nil {
		return config.Tenant{}, accountCredentials{}, err
	}
	ftpPass, err := secret(20)
	if err != nil {
		return config.Tenant{}, accountCredentials{}, err
	}
	s3Access, err := secret(10)
	if err != nil {
		return config.Tenant{}, accountCredentials{}, err
	}
	s3Secret, err := secret(32)
	if err != nil {
		return config.Tenant{}, accountCredentials{}, err
	}
	sum := sha256.Sum256([]byte(apiKey))
	tenant := config.Tenant{ID: id, Weight: weight, APIKeySHA256: hex.EncodeToString(sum[:]), SFTPUser: id, SFTPPassword: sftpPass, FTPUser: id, FTPPassword: ftpPass, AllowPlainFTP: allowPlainFTP, S3Bucket: bucket, S3AccessKey: s3Access, S3SecretKey: s3Secret, MaxUploadBPS: maxUploadBPS, MaxConcurrent: maxConcurrent}
	return tenant, accountCredentials{apiKey: apiKey, sftpPassword: sftpPass, ftpPassword: ftpPass, s3Secret: s3Secret}, nil
}

func validS3Bucket(name string) bool {
	if len(name) < 3 || len(name) > 63 || strings.Contains(name, "..") || net.ParseIP(name) != nil {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(name)-1) || (r == '.' && i > 0 && i < len(name)-1) {
			continue
		}
		return false
	}
	return true
}

func printCredentials(configPath string, tenant config.Tenant, bundlePath string) {
	fmt.Printf("config: %s\naccount: %s\nclient connection bundle: %s\n", configPath, tenant.ID, bundlePath)
	fmt.Println("the bundle contains account secrets; copy it securely and keep its permissions at 0600")
}

func healthcheckCommand(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:9090/metrics", "health endpoint URL")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func serveCommand(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cfg, logger)
}
func validateCommand(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, err := config.Load(*configPath)
	if err == nil {
		fmt.Println("configuration is valid")
	}
	return err
}

func initCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	configPath := fs.String("config", "./xsync.yaml", "output configuration")
	dataDir := fs.String("data-dir", "/mnt/xsync", "mounted data directory")
	advertiseIP := fs.String("advertise-ip", "127.0.0.1", "IP address in TLS certificate")
	force := fs.Bool("force", false, "replace generated files")
	requireMount := fs.Bool("require-mount", true, "require data-dir to be a distinct mount point")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*force {
		if _, err := os.Stat(*configPath); err == nil {
			return fmt.Errorf("config already exists: %s", *configPath)
		}
	}
	dir := filepath.Dir(*configPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	certPath, keyPath, hostKeyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ssh_host_ed25519_key")
	if err := generateTLS(certPath, keyPath, *advertiseIP); err != nil {
		return err
	}
	if err := generateSSHKey(hostKeyPath); err != nil {
		return err
	}
	cfg := config.Default()
	cfg.PublicHost = *advertiseIP
	cfg.AccountsFile = filepath.Join(dir, "accounts.yaml")
	cfg.DataDir = *dataDir
	cfg.RequireMount = *requireMount
	cfg.TLS = config.TLSConfig{CertFile: certPath, KeyFile: keyPath}
	cfg.SFTP.HostKeyFile = hostKeyPath
	cfg.FTP.PublicHost = *advertiseIP
	cfg.Tenants = []config.Tenant{}
	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("config: %s\nservice initialized with no accounts\n", *configPath)
	fmt.Println("create an account with: xsync-server account add --id <account>")
	return nil
}

func secret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func generateTLS(certFile, keyFile, ipText string) error {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return fmt.Errorf("invalid advertise IP: %s", ipText)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "xsync"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
}
func generateSSHKey(name string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	return os.WriteFile(name, pem.EncodeToMemory(block), 0o600)
}
