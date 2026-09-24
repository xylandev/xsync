package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/platform"
)

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// initCommand prepares a configuration directory. It is safe to rerun with
// --force: existing accounts, keys and the CA are kept unless explicitly
// regenerated, so a mistaken rerun cannot wipe a deployment.
func initCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	configPath := fs.String("config", "./xsync.yaml", "output configuration")
	dataDir := fs.String("data-dir", "/mnt/xsync", "mounted data directory")
	advertiseIP := fs.String("advertise-ip", "127.0.0.1", "IP address clients use (certificate SAN and FTP passive address)")
	dns := fs.String("dns", "", "optional comma-separated DNS names for the certificate")
	force := fs.Bool("force", false, "rewrite an existing configuration (accounts and keys are kept)")
	regenerateCA := fs.Bool("regenerate-ca", false, "with --force: create a new CA (every connection bundle must be reissued)")
	regenerateSSH := fs.Bool("regenerate-ssh-key", false, "with --force: create a new SSH host key (clients see a changed host key)")
	requireMount := fs.Bool("require-mount", true, "require data-dir to be a distinct mount point")
	metricsListen := fs.String("metrics-listen", "127.0.0.1:9090", "metrics and admin API address (use 0.0.0.0:9090 inside a container)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if exists(*configPath) && !*force {
		return fmt.Errorf("config already exists: %s (use --force to rewrite it; accounts are kept)", *configPath)
	}
	ips, names, err := parseAddresses(*advertiseIP, *dns)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("--advertise-ip is required: FTP passive mode needs an IP address")
	}
	// Every generated path is absolute: relative paths in the configuration
	// resolve against the configuration's directory, and a relative config
	// path given here would otherwise be applied twice.
	dir, err := filepath.Abs(filepath.Dir(*configPath))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
	}
	paths := struct{ ca, caKey, cert, key, ssh, secrets, token, accounts string }{
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"),
		filepath.Join(dir, "ssh_host_ed25519_key"), filepath.Join(dir, "secrets.key"), filepath.Join(dir, "admin.token"), filepath.Join(dir, "accounts.yaml"),
	}
	var kept []string
	if !exists(paths.ca) || !exists(paths.caKey) || *regenerateCA {
		if err := generateCA(paths.ca, paths.caKey); err != nil {
			return err
		}
	} else {
		kept = append(kept, "CA")
	}
	if err := issueLeaf(paths.ca, paths.caKey, paths.cert, paths.key, ips, names, leafValidity); err != nil {
		return err
	}
	if !exists(paths.ssh) || *regenerateSSH {
		if err := generateSSHKey(paths.ssh); err != nil {
			return err
		}
	} else {
		kept = append(kept, "SSH host key")
	}
	if !exists(paths.secrets) {
		if err := config.GenerateSecretsKey(paths.secrets); err != nil {
			return err
		}
	} else {
		kept = append(kept, "secrets key")
	}
	if !exists(paths.token) {
		token, err := secret(32)
		if err != nil {
			return err
		}
		if err := config.WriteFileAtomic(paths.token, []byte(token+"\n"), 0o600); err != nil {
			return err
		}
	} else {
		kept = append(kept, "admin token")
	}

	cfg := config.Default()
	if exists(*configPath) {
		if old, err := config.Load(*configPath); err == nil {
			cfg = old
		}
	}
	cfg.PublicHost = ips[0].String()
	cfg.FTP.PublicHost = cfg.PublicHost
	cfg.AccountsFile = paths.accounts
	cfg.SecretsKeyFile = paths.secrets
	cfg.AdminTokenFile = paths.token
	cfg.DataDir = *dataDir
	cfg.RequireMount = *requireMount
	cfg.TLS = config.TLSConfig{CertFile: paths.cert, KeyFile: paths.key, CACertFile: paths.ca, CAKeyFile: paths.caKey}
	cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCACertFile, cfg.TLSCAKeyFile = "", "", "", ""
	cfg.SFTP.HostKeyFile = paths.ssh
	cfg.Metrics.Listen, cfg.MetricsListen = *metricsListen, ""
	if exists(paths.accounts) {
		kept = append(kept, "accounts")
		probe := cfg
		probe.Tenants = nil
		if cfg.Tenants, err = probe.LoadAccountsFrom(paths.accounts); err != nil {
			return fmt.Errorf("existing accounts file is unreadable, refusing to overwrite it: %w", err)
		}
	} else {
		cfg.Tenants = []config.Tenant{}
	}

	// Mark the data volume so the server refuses to start on an empty
	// directory when the real volume is not mounted.
	if err := os.MkdirAll(*dataDir, 0o750); err == nil {
		id, err := platform.ReadVolumeMarker(*dataDir)
		if err != nil {
			if id, err = secret(8); err == nil {
				err = platform.WriteVolumeMarker(*dataDir, id)
			}
		}
		if err == nil {
			cfg.DataVolumeID = id
		} else {
			fmt.Fprintf(os.Stderr, "warning: could not mark the data volume: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: data directory %s is not reachable here; run 'xsync-server volume adopt' where it is mounted\n", *dataDir)
	}
	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("config: %s\n", *configPath)
	if len(kept) > 0 {
		fmt.Printf("kept existing: %v\n", kept)
	}
	if len(cfg.Tenants) == 0 {
		fmt.Println("service initialized with no accounts; create one with: xsync-server account add --id <account>")
	}
	fmt.Printf("serving certificate valid until %s; renew with 'xsync-server cert renew'\n", time.Now().Add(leafValidity).Format("2006-01-02"))
	return nil
}

// volumeCommand manages the data volume marker.
func volumeCommand(args []string) error {
	if len(args) == 0 || args[0] != "adopt" {
		return errors.New("usage: xsync-server volume adopt --config <file>")
	}
	fs := flag.NewFlagSet("volume adopt", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if !exists(filepath.Join(cfg.DataDir, "metadata", "catalog.db")) {
		return fmt.Errorf("%s holds no catalog; adopt only a data directory that already contains xsync data", cfg.DataDir)
	}
	id, err := platform.ReadVolumeMarker(cfg.DataDir)
	if err != nil {
		if id, err = secret(8); err != nil {
			return err
		}
		if err = platform.WriteVolumeMarker(cfg.DataDir, id); err != nil {
			return err
		}
	}
	if err := config.Update(*configPath, func(c *config.Config) error { c.DataVolumeID = id; return nil }); err != nil {
		return err
	}
	fmt.Printf("data volume %s adopted as %s\n", cfg.DataDir, id)
	return nil
}
