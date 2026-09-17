package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PublicHost   string         `yaml:"public_host,omitempty"`
	AccountsFile string         `yaml:"accounts_file,omitempty"`
	TLSCertFile  string         `yaml:"tls_cert,omitempty"`
	TLSKeyFile   string         `yaml:"tls_key,omitempty"`
	SSHHostKey   string         `yaml:"ssh_host_key,omitempty"`
	DataDir      string         `yaml:"data_dir"`
	RequireMount bool           `yaml:"require_mount"`
	TLS          TLSConfig      `yaml:"tls"`
	Download     ListenerConfig `yaml:"download"`
	Metrics      ListenerConfig `yaml:"metrics"`
	SFTP         SFTPConfig     `yaml:"sftp"`
	FTP          FTPConfig      `yaml:"ftp"`
	S3           S3Config       `yaml:"s3"`
	Capacity     CapacityConfig `yaml:"capacity"`
	PartialTTL   time.Duration  `yaml:"partial_ttl"`
	Tenants      []Tenant       `yaml:"tenants"`
}

type compactConfig struct {
	DataDir      string `yaml:"data_dir"`
	PublicHost   string `yaml:"public_host"`
	AccountsFile string `yaml:"accounts_file"`
	RequireMount *bool  `yaml:"require_mount,omitempty"`
	TLSCertFile  string `yaml:"tls_cert,omitempty"`
	TLSKeyFile   string `yaml:"tls_key,omitempty"`
	SSHHostKey   string `yaml:"ssh_host_key,omitempty"`
}

type accountDocument struct {
	Accounts []Tenant `yaml:"accounts"`
}

type ListenerConfig struct {
	Listen string `yaml:"listen"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SFTPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Listen      string `yaml:"listen"`
	HostKeyFile string `yaml:"host_key_file"`
}

type FTPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Listen       string `yaml:"listen"`
	PublicHost   string `yaml:"public_host"`
	PassiveStart int    `yaml:"passive_start"`
	PassiveEnd   int    `yaml:"passive_end"`
}

type S3Config struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type CapacityConfig struct {
	SoftPercent     float64       `yaml:"soft_percent"`
	HardPercent     float64       `yaml:"hard_percent"`
	CriticalPercent float64       `yaml:"critical_percent"`
	TargetRunway    time.Duration `yaml:"target_runway"`
	MaxUploadBPS    int64         `yaml:"max_upload_bps"`
	MinFreeBytes    uint64        `yaml:"min_free_bytes"`
}

type Tenant struct {
	ID             string   `yaml:"id"`
	Weight         int      `yaml:"weight"`
	APIKeySHA256   string   `yaml:"api_key_sha256"`
	SFTPUser       string   `yaml:"sftp_user"`
	SFTPPassword   string   `yaml:"sftp_password"`
	AuthorizedKeys []string `yaml:"authorized_keys"`
	FTPUser        string   `yaml:"ftp_user"`
	FTPPassword    string   `yaml:"ftp_password"`
	AllowPlainFTP  bool     `yaml:"allow_plain_ftp"`
	S3Bucket       string   `yaml:"s3_bucket"`
	S3AccessKey    string   `yaml:"s3_access_key"`
	S3SecretKey    string   `yaml:"s3_secret_key"`
	MaxUploadBPS   int64    `yaml:"max_upload_bps"`
	MaxConcurrent  int      `yaml:"max_concurrent"`
}

func Default() Config {
	return Config{
		DataDir:      "/mnt/xsync",
		RequireMount: true,
		TLS:          TLSConfig{CertFile: "/etc/xsync/tls.crt", KeyFile: "/etc/xsync/tls.key"},
		Download:     ListenerConfig{Listen: ":9443"},
		Metrics:      ListenerConfig{Listen: "127.0.0.1:9090"},
		SFTP:         SFTPConfig{Enabled: true, Listen: ":2022", HostKeyFile: "/etc/xsync/ssh_host_ed25519_key"},
		FTP:          FTPConfig{Enabled: true, Listen: ":2121", PassiveStart: 30000, PassiveEnd: 30100},
		S3:           S3Config{Enabled: true, Listen: ":9000"},
		Capacity: CapacityConfig{
			SoftPercent: 75, HardPercent: 90, CriticalPercent: 95,
			TargetRunway: 30 * time.Minute, MinFreeBytes: 5 << 30,
		},
		PartialTTL: 24 * time.Hour,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.PublicHost != "" {
		cfg.FTP.PublicHost = cfg.PublicHost
	}
	if cfg.TLSCertFile != "" {
		cfg.TLS.CertFile = cfg.TLSCertFile
	}
	if cfg.TLSKeyFile != "" {
		cfg.TLS.KeyFile = cfg.TLSKeyFile
	}
	if cfg.SSHHostKey != "" {
		cfg.SFTP.HostKeyFile = cfg.SSHHostKey
	}
	if cfg.AccountsFile != "" {
		accountPath := resolvePath(path, cfg.AccountsFile)
		raw, readErr := os.ReadFile(accountPath)
		if readErr != nil {
			return Config{}, fmt.Errorf("read accounts: %w", readErr)
		}
		var doc accountDocument
		if unmarshalErr := yaml.Unmarshal(raw, &doc); unmarshalErr != nil {
			return Config{}, fmt.Errorf("decode accounts: %w", unmarshalErr)
		}
		cfg.Tenants = doc.Accounts
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Write(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.AccountsFile != "" {
		accountPath := resolvePath(path, cfg.AccountsFile)
		if err := writeYAML(accountPath, accountDocument{Accounts: cfg.Tenants}); err != nil {
			return err
		}
		publicHost := cfg.PublicHost
		if publicHost == "" {
			publicHost = cfg.FTP.PublicHost
		}
		compact := compactConfig{DataDir: cfg.DataDir, PublicHost: publicHost, AccountsFile: cfg.AccountsFile}
		defaults := Default()
		if cfg.RequireMount != defaults.RequireMount {
			compact.RequireMount = &cfg.RequireMount
		}
		if cfg.TLS.CertFile != defaults.TLS.CertFile {
			compact.TLSCertFile = cfg.TLS.CertFile
		}
		if cfg.TLS.KeyFile != defaults.TLS.KeyFile {
			compact.TLSKeyFile = cfg.TLS.KeyFile
		}
		if cfg.SFTP.HostKeyFile != defaults.SFTP.HostKeyFile {
			compact.SSHHostKey = cfg.SFTP.HostKeyFile
		}
		return writeYAML(path, compact)
	}
	return writeYAML(path, cfg)
}

func writeYAML(path string, value any) error {
	b, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xsync-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(b)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func resolvePath(configPath, value string) string {
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(filepath.Dir(configPath), value)
}

func Update(path string, update func(*Config) error) error {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	if err = update(&cfg); err != nil {
		return err
	}
	if err = cfg.Validate(); err != nil {
		return err
	}
	return Write(path, cfg)
}

func AddTenant(configPath string, tenant Tenant) error {
	cfg, err := Load(configPath)
	if err != nil {
		return err
	}
	if cfg.AccountsFile == "" {
		return Update(configPath, func(current *Config) error {
			current.Tenants = append(current.Tenants, tenant)
			if compactCompatible(*current) {
				current.PublicHost = current.FTP.PublicHost
				current.AccountsFile = filepath.Join(filepath.Dir(configPath), "accounts.yaml")
			}
			return nil
		})
	}
	accountPath := resolvePath(configPath, cfg.AccountsFile)
	lock, err := os.OpenFile(accountPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, err := os.ReadFile(accountPath)
	if err != nil {
		return err
	}
	var doc accountDocument
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc.Accounts = append(doc.Accounts, tenant)
	candidate := cfg
	candidate.Tenants = doc.Accounts
	if err = candidate.Validate(); err != nil {
		return err
	}
	return writeYAML(accountPath, doc)
}

func compactCompatible(cfg Config) bool {
	defaults := Default()
	return cfg.Download == defaults.Download &&
		cfg.Metrics == defaults.Metrics &&
		cfg.SFTP.Enabled == defaults.SFTP.Enabled &&
		cfg.SFTP.Listen == defaults.SFTP.Listen &&
		cfg.FTP.Enabled == defaults.FTP.Enabled &&
		cfg.FTP.Listen == defaults.FTP.Listen &&
		cfg.FTP.PassiveStart == defaults.FTP.PassiveStart &&
		cfg.FTP.PassiveEnd == defaults.FTP.PassiveEnd &&
		cfg.S3 == defaults.S3 &&
		cfg.Capacity == defaults.Capacity &&
		cfg.PartialTTL == defaults.PartialTTL
}

func (c Config) Validate() error {
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		return errors.New("data_dir must be an absolute path")
	}
	if !(c.Capacity.SoftPercent > 0 && c.Capacity.SoftPercent < c.Capacity.HardPercent && c.Capacity.HardPercent < c.Capacity.CriticalPercent && c.Capacity.CriticalPercent < 100) {
		return errors.New("capacity watermarks must satisfy 0 < soft < hard < critical < 100")
	}
	if c.Capacity.TargetRunway <= 0 {
		return errors.New("capacity.target_runway must be positive")
	}
	if c.PartialTTL <= 0 {
		return errors.New("partial_ttl must be positive")
	}
	if c.Download.Listen == "" {
		return errors.New("download.listen is required")
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return errors.New("tls.cert_file and tls.key_file are required")
	}
	if c.SFTP.Enabled && c.SFTP.HostKeyFile == "" {
		return errors.New("sftp.host_key_file is required when SFTP is enabled")
	}
	if c.FTP.Enabled && (c.FTP.PassiveStart < 1 || c.FTP.PassiveEnd < c.FTP.PassiveStart || c.FTP.PassiveEnd > 65535) {
		return errors.New("invalid FTP passive port range")
	}
	for name, addr := range map[string]string{"download": c.Download.Listen, "metrics": c.Metrics.Listen, "sftp": c.SFTP.Listen, "ftp": c.FTP.Listen, "s3": c.S3.Listen} {
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s listen address: %w", name, err)
		}
	}
	seen := map[string]bool{}
	sftpUsers := map[string]bool{}
	ftpUsers := map[string]bool{}
	s3Access := map[string]bool{}
	s3Buckets := map[string]bool{}
	apiDigests := map[string]bool{}
	for _, t := range c.Tenants {
		if t.ID == "" || strings.ContainsAny(t.ID, "/\\\x00") || seen[t.ID] {
			return fmt.Errorf("tenant IDs must be non-empty and unique: %q", t.ID)
		}
		seen[t.ID] = true
		if t.Weight < 0 || t.MaxConcurrent < 0 || t.MaxUploadBPS < 0 {
			return fmt.Errorf("tenant %q has an invalid limit", t.ID)
		}
		_, digestErr := hex.DecodeString(t.APIKeySHA256)
		if digestErr != nil || len(t.APIKeySHA256) != 64 || apiDigests[strings.ToLower(t.APIKeySHA256)] {
			return fmt.Errorf("tenant %q must have a unique SHA-256 API key digest", t.ID)
		}
		apiDigests[strings.ToLower(t.APIKeySHA256)] = true
		if c.SFTP.Enabled {
			if t.SFTPUser == "" || len(t.SFTPPassword) < 12 || sftpUsers[t.SFTPUser] {
				return fmt.Errorf("tenant %q must have unique SFTP credentials", t.ID)
			}
			sftpUsers[t.SFTPUser] = true
		}
		if c.FTP.Enabled {
			if t.FTPUser == "" || len(t.FTPPassword) < 12 || ftpUsers[t.FTPUser] {
				return fmt.Errorf("tenant %q must have unique FTP credentials", t.ID)
			}
			ftpUsers[t.FTPUser] = true
		}
		if c.S3.Enabled {
			if t.S3Bucket == "" || t.S3AccessKey == "" || len(t.S3SecretKey) < 16 || s3Access[t.S3AccessKey] || s3Buckets[t.S3Bucket] {
				return fmt.Errorf("tenant %q must have unique S3 bucket and credentials", t.ID)
			}
			s3Access[t.S3AccessKey] = true
			s3Buckets[t.S3Bucket] = true
		}
	}
	return nil
}
