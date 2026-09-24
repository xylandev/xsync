package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PublicHost     string `yaml:"public_host,omitempty"`
	AccountsFile   string `yaml:"accounts_file,omitempty"`
	TLSCertFile    string `yaml:"tls_cert,omitempty"`
	TLSKeyFile     string `yaml:"tls_key,omitempty"`
	TLSCACertFile  string `yaml:"tls_ca_cert,omitempty"`
	TLSCAKeyFile   string `yaml:"tls_ca_key,omitempty"`
	SSHHostKey     string `yaml:"ssh_host_key,omitempty"`
	MetricsListen  string `yaml:"metrics_listen,omitempty"`
	SecretsKeyFile string `yaml:"secrets_key_file,omitempty"`
	AdminTokenFile string `yaml:"admin_token_file,omitempty"`
	// DataVolumeID must match the marker file init writes into data_dir. It
	// keeps the server from writing into an empty directory when the real data
	// volume failed to mount.
	DataVolumeID  string         `yaml:"data_volume_id,omitempty"`
	DataDir       string         `yaml:"data_dir"`
	RequireMount  bool           `yaml:"require_mount"`
	TLS           TLSConfig      `yaml:"tls"`
	Download      ListenerConfig `yaml:"download"`
	Metrics       ListenerConfig `yaml:"metrics"`
	SFTP          SFTPConfig     `yaml:"sftp"`
	FTP           FTPConfig      `yaml:"ftp"`
	S3            S3Config       `yaml:"s3"`
	Capacity      CapacityConfig `yaml:"capacity"`
	Limits        LimitsConfig   `yaml:"limits"`
	Delivery      DeliveryConfig `yaml:"delivery"`
	PartialTTL    time.Duration  `yaml:"partial_ttl"`
	ShutdownGrace time.Duration  `yaml:"shutdown_grace"`
	Tenants       []Tenant       `yaml:"tenants"`

	// configPath is where the configuration was loaded from; account writes
	// and relative paths resolve against it.
	configPath string
}

type compactConfig struct {
	DataDir        string `yaml:"data_dir"`
	PublicHost     string `yaml:"public_host"`
	AccountsFile   string `yaml:"accounts_file"`
	DataVolumeID   string `yaml:"data_volume_id,omitempty"`
	RequireMount   *bool  `yaml:"require_mount,omitempty"`
	TLSCertFile    string `yaml:"tls_cert,omitempty"`
	TLSKeyFile     string `yaml:"tls_key,omitempty"`
	TLSCACertFile  string `yaml:"tls_ca_cert,omitempty"`
	TLSCAKeyFile   string `yaml:"tls_ca_key,omitempty"`
	SSHHostKey     string `yaml:"ssh_host_key,omitempty"`
	MetricsListen  string `yaml:"metrics_listen,omitempty"`
	SecretsKeyFile string `yaml:"secrets_key_file,omitempty"`
	AdminTokenFile string `yaml:"admin_token_file,omitempty"`
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
	// CACertFile/CAKeyFile hold the long-lived CA that signs the short-lived
	// serving certificate. Connection bundles pin the CA, so the serving
	// certificate can be renewed without reissuing them.
	CACertFile string `yaml:"ca_cert_file,omitempty"`
	CAKeyFile  string `yaml:"ca_key_file,omitempty"`
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
	// CloseGrace is how long an FTP upload waits after the data connection
	// ends before it is published. FTP stream mode cannot tell a finished
	// transfer from a dropped one; a control connection that disappears within
	// this window marks the upload as interrupted instead.
	CloseGrace time.Duration `yaml:"close_grace"`
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
	// UploadSlotWait bounds how long a new upload waits for one of the
	// tenant's max_concurrent slots before it is rejected as busy.
	UploadSlotWait time.Duration `yaml:"upload_slot_wait"`
}

// LimitsConfig protects the listeners from abusive or broken peers.
type LimitsConfig struct {
	MaxConnections         int           `yaml:"max_connections"`
	MaxConnectionsPerIP    int           `yaml:"max_connections_per_ip"`
	HandshakeTimeout       time.Duration `yaml:"handshake_timeout"`
	IdleTimeout            time.Duration `yaml:"idle_timeout"`
	AuthFailuresPerMinute  int           `yaml:"auth_failures_per_minute"`
	MaxOpenFilesPerSession int           `yaml:"max_open_files_per_session"`
	MaxRequestBody         int64         `yaml:"max_request_body"`
}

type DeliveryConfig struct {
	// MaxAttempts is how many times an object may be handed to a downloader
	// before it is parked (dead-lettered). Tenants may override it.
	MaxAttempts  int           `yaml:"max_attempts"`
	MaxLease     time.Duration `yaml:"max_lease"`
	TombstoneTTL time.Duration `yaml:"tombstone_ttl"`
	MaxLongPoll  time.Duration `yaml:"max_long_poll"`
	MaxBatch     int           `yaml:"max_batch"`
}

const (
	OverwriteSupersede = "supersede"
	OverwriteKeep      = "keep"
)

// DefaultHoldPatterns are the temporary names common upload tools write to
// before renaming the finished file into place: WinSCP (*.filepart), rclone
// (*.partial) and many scripts (*.tmp).
var DefaultHoldPatterns = []string{"*.filepart", "*.partial", "*.tmp"}

type Tenant struct {
	ID       string `yaml:"id"`
	Disabled bool   `yaml:"disabled,omitempty"`
	Weight   int    `yaml:"weight"`
	// APIKeySHA256 is the SHA-256 of the download API key; the key itself is
	// only ever handed out in the connection bundle.
	APIKeySHA256 string `yaml:"api_key_sha256"`
	SFTPUser     string `yaml:"sftp_user"`
	// SFTPPassword/FTPPassword are legacy plaintext fields. Every account
	// write replaces them with a salted hash.
	SFTPPassword     string   `yaml:"sftp_password,omitempty"`
	SFTPPasswordHash string   `yaml:"sftp_password_hash,omitempty"`
	AuthorizedKeys   []string `yaml:"authorized_keys,omitempty"`
	FTPUser          string   `yaml:"ftp_user"`
	FTPPassword      string   `yaml:"ftp_password,omitempty"`
	FTPPasswordHash  string   `yaml:"ftp_password_hash,omitempty"`
	AllowPlainFTP    bool     `yaml:"allow_plain_ftp"`
	S3Bucket         string   `yaml:"s3_bucket"`
	S3AccessKey      string   `yaml:"s3_access_key"`
	// S3SecretKey is kept in memory in plaintext because SigV4 needs it. On
	// disk it is encrypted with the secrets key when one is configured.
	S3SecretKey    string `yaml:"s3_secret_key"`
	MaxUploadBPS   int64  `yaml:"max_upload_bps"`
	MaxConcurrent  int    `yaml:"max_concurrent"`
	MaxStoredBytes int64  `yaml:"max_stored_bytes,omitempty"`
	// Overwrite decides what happens to undelivered older versions when a
	// path is uploaded again: "supersede" (default) drops them, "keep"
	// delivers every version.
	Overwrite string `yaml:"overwrite,omitempty"`
	// HoldPatterns are basename globs for client temporary files that are
	// held back from delivery until renamed. Nil means DefaultHoldPatterns;
	// NoHold disables holding entirely.
	HoldPatterns []string      `yaml:"hold_patterns,omitempty"`
	NoHold       bool          `yaml:"no_hold,omitempty"`
	PublishDelay time.Duration `yaml:"publish_delay,omitempty"`
	MaxAttempts  int           `yaml:"max_attempts,omitempty"`
}

// EffectiveHoldPatterns returns the hold globs in force for the tenant.
func (t Tenant) EffectiveHoldPatterns() []string {
	if t.NoHold {
		return nil
	}
	if t.HoldPatterns == nil {
		return DefaultHoldPatterns
	}
	return t.HoldPatterns
}

// EffectiveOverwrite returns the overwrite policy in force for the tenant.
func (t Tenant) EffectiveOverwrite() string {
	if t.Overwrite == "" {
		return OverwriteSupersede
	}
	return t.Overwrite
}

func Default() Config {
	return Config{
		DataDir:      "/mnt/xsync",
		RequireMount: true,
		TLS:          TLSConfig{CertFile: "/etc/xsync/tls.crt", KeyFile: "/etc/xsync/tls.key"},
		Download:     ListenerConfig{Listen: ":9443"},
		Metrics:      ListenerConfig{Listen: "127.0.0.1:9090"},
		SFTP:         SFTPConfig{Enabled: true, Listen: ":2022", HostKeyFile: "/etc/xsync/ssh_host_ed25519_key"},
		FTP:          FTPConfig{Enabled: true, Listen: ":2121", PassiveStart: 30000, PassiveEnd: 30100, CloseGrace: 200 * time.Millisecond},
		S3:           S3Config{Enabled: true, Listen: ":9000"},
		Capacity: CapacityConfig{
			SoftPercent: 75, HardPercent: 90, CriticalPercent: 95,
			TargetRunway: 30 * time.Minute, MinFreeBytes: 5 << 30,
			UploadSlotWait: 10 * time.Second,
		},
		Limits: LimitsConfig{
			MaxConnections: 2000, MaxConnectionsPerIP: 128,
			HandshakeTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute,
			AuthFailuresPerMinute: 20, MaxOpenFilesPerSession: 64,
			MaxRequestBody: 2 << 20,
		},
		Delivery: DeliveryConfig{
			MaxAttempts: 10, MaxLease: time.Hour, TombstoneTTL: 7 * 24 * time.Hour,
			MaxLongPoll: 30 * time.Second, MaxBatch: 64,
		},
		PartialTTL:    24 * time.Hour,
		ShutdownGrace: 40 * time.Second,
	}
}

// Path returns the file the configuration was loaded from, if any.
func (c Config) Path() string { return c.configPath }

// ResolvedAccountsFile returns the absolute accounts file path, or "".
func (c Config) ResolvedAccountsFile() string {
	if c.AccountsFile == "" {
		return ""
	}
	return resolvePath(c.configPath, c.AccountsFile)
}

func Load(path string) (Config, error) {
	cfg, err := loadUnvalidated(path)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadUnvalidated(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(string(b)) != "" {
		// Unknown keys are almost always typos; ignoring them would silently
		// run with a default the operator meant to change.
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("decode config: %w", err)
		}
	}
	cfg.configPath = path
	cfg.applyAliases()
	if cfg.AccountsFile != "" {
		tenants, err := readAccounts(cfg.ResolvedAccountsFile(), cfg.secretsKeyPath())
		if err != nil {
			return Config{}, err
		}
		cfg.Tenants = tenants
	}
	return cfg, nil
}

func (c *Config) applyAliases() {
	if c.PublicHost != "" {
		c.FTP.PublicHost = c.PublicHost
	}
	if c.TLSCertFile != "" {
		c.TLS.CertFile = c.TLSCertFile
	}
	if c.TLSKeyFile != "" {
		c.TLS.KeyFile = c.TLSKeyFile
	}
	if c.TLSCACertFile != "" {
		c.TLS.CACertFile = c.TLSCACertFile
	}
	if c.TLSCAKeyFile != "" {
		c.TLS.CAKeyFile = c.TLSCAKeyFile
	}
	if c.SSHHostKey != "" {
		c.SFTP.HostKeyFile = c.SSHHostKey
	}
	if c.MetricsListen != "" {
		c.Metrics.Listen = c.MetricsListen
	}
}

func (c Config) secretsKeyPath() string {
	if c.SecretsKeyFile == "" {
		return ""
	}
	return resolvePath(c.configPath, c.SecretsKeyFile)
}

// AdminTokenPath returns the resolved admin token file, or "".
func (c Config) AdminTokenPath() string {
	if c.AdminTokenFile == "" {
		return ""
	}
	return resolvePath(c.configPath, c.AdminTokenFile)
}

func readAccounts(accountPath, keyPath string) ([]Tenant, error) {
	raw, err := os.ReadFile(accountPath)
	if err != nil {
		return nil, fmt.Errorf("read accounts: %w", err)
	}
	var doc accountDocument
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode accounts: %w", err)
	}
	key, err := loadSecretsKey(keyPath)
	if err != nil {
		return nil, err
	}
	for i := range doc.Accounts {
		if doc.Accounts[i].S3SecretKey, err = openSecret(key, doc.Accounts[i].S3SecretKey); err != nil {
			return nil, fmt.Errorf("account %q: %w", doc.Accounts[i].ID, err)
		}
	}
	if doc.Accounts == nil {
		doc.Accounts = []Tenant{}
	}
	return doc.Accounts, nil
}

// LoadAccounts rereads only the accounts file of an already loaded
// configuration. The server uses it to apply account changes without a
// restart.
func (c Config) LoadAccounts() ([]Tenant, error) {
	if c.AccountsFile == "" {
		fresh, err := Load(c.configPath)
		if err != nil {
			return nil, err
		}
		return fresh.Tenants, nil
	}
	tenants, err := readAccounts(c.ResolvedAccountsFile(), c.secretsKeyPath())
	if err != nil {
		return nil, err
	}
	candidate := c
	candidate.Tenants = tenants
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	return tenants, nil
}

func Write(path string, cfg Config) error {
	cfg.configPath = path
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.AccountsFile != "" {
		if err := writeAccounts(resolvePath(path, cfg.AccountsFile), cfg.secretsKeyPath(), cfg.Tenants); err != nil {
			return err
		}
		publicHost := cfg.PublicHost
		if publicHost == "" {
			publicHost = cfg.FTP.PublicHost
		}
		compact := compactConfig{DataDir: cfg.DataDir, PublicHost: publicHost, AccountsFile: cfg.AccountsFile, DataVolumeID: cfg.DataVolumeID, SecretsKeyFile: cfg.SecretsKeyFile, AdminTokenFile: cfg.AdminTokenFile}
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
		compact.TLSCACertFile = cfg.TLS.CACertFile
		compact.TLSCAKeyFile = cfg.TLS.CAKeyFile
		if cfg.SFTP.HostKeyFile != defaults.SFTP.HostKeyFile {
			compact.SSHHostKey = cfg.SFTP.HostKeyFile
		}
		if cfg.Metrics.Listen != defaults.Metrics.Listen {
			compact.MetricsListen = cfg.Metrics.Listen
		}
		if !compactCompatible(cfg) {
			// Settings the short form cannot express must survive: write the
			// full document (still without secrets, which live in accounts).
			full := cfg
			full.Tenants = nil
			return writeYAML(path, full)
		}
		return writeYAML(path, compact)
	}
	return writeYAML(path, cfg)
}

func writeAccounts(accountPath, keyPath string, tenants []Tenant) error {
	key, err := loadSecretsKey(keyPath)
	if err != nil {
		return err
	}
	out := make([]Tenant, len(tenants))
	for i, t := range tenants {
		if t.SFTPPassword != "" && t.SFTPPasswordHash == "" {
			if t.SFTPPasswordHash, err = HashSecret(t.SFTPPassword); err != nil {
				return err
			}
		}
		if t.FTPPassword != "" && t.FTPPasswordHash == "" {
			if t.FTPPasswordHash, err = HashSecret(t.FTPPassword); err != nil {
				return err
			}
		}
		t.SFTPPassword, t.FTPPassword = "", ""
		if t.S3SecretKey, err = sealSecret(key, t.S3SecretKey); err != nil {
			return err
		}
		out[i] = t
	}
	return writeYAML(accountPath, accountDocument{Accounts: out})
}

func writeYAML(path string, value any) error {
	b, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, b, 0o600)
}

// WriteFileAtomic replaces path with data via a synced temporary file and a
// rename, then syncs the directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xsync-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(perm); err == nil {
		_, err = tmp.Write(data)
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
	if filepath.IsAbs(value) || configPath == "" {
		return value
	}
	return filepath.Join(filepath.Dir(configPath), value)
}

func lockFile(name string) (func(), error) {
	lock, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}

func Update(path string, update func(*Config) error) error {
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
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

// UpdateAccounts applies fn to the account list under the accounts file lock
// and writes the result atomically. Legacy configurations that embed their
// tenants are migrated to a separate accounts file on the way.
func UpdateAccounts(configPath string, fn func([]Tenant) ([]Tenant, error)) error {
	cfg, err := Load(configPath)
	if err != nil {
		return err
	}
	if cfg.AccountsFile == "" {
		return Update(configPath, func(current *Config) error {
			tenants, err := fn(append([]Tenant(nil), current.Tenants...))
			if err != nil {
				return err
			}
			current.Tenants = tenants
			if compactCompatible(*current) {
				current.PublicHost = current.FTP.PublicHost
				current.AccountsFile = filepath.Join(filepath.Dir(configPath), "accounts.yaml")
			}
			return nil
		})
	}
	accountPath := cfg.ResolvedAccountsFile()
	unlock, err := lockFile(accountPath + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	current, err := readAccounts(accountPath, cfg.secretsKeyPath())
	if err != nil {
		return err
	}
	next, err := fn(current)
	if err != nil {
		return err
	}
	candidate := cfg
	candidate.Tenants = next
	if err = candidate.Validate(); err != nil {
		return err
	}
	return writeAccounts(accountPath, cfg.secretsKeyPath(), next)
}

func AddTenant(configPath string, tenant Tenant) error {
	return UpdateAccounts(configPath, func(ts []Tenant) ([]Tenant, error) {
		for _, t := range ts {
			if t.ID == tenant.ID {
				return nil, fmt.Errorf("account %q already exists", tenant.ID)
			}
		}
		return append(ts, tenant), nil
	})
}

// compactCompatible reports whether cfg can be written in the short form without
// losing anything.
//
// It rebuilds a config from the defaults plus exactly the fields the compact
// form can express, and demands an exact match. Comparing field by field would
// silently discard a user's setting whenever a new field is added and someone
// forgets to extend this check; rebuilding makes any unrecognised difference
// fall back to the full format instead.
func compactCompatible(cfg Config) bool {
	rebuilt := Default()
	rebuilt.configPath = cfg.configPath
	rebuilt.DataDir = cfg.DataDir
	rebuilt.PublicHost = cfg.PublicHost
	rebuilt.AccountsFile = cfg.AccountsFile
	rebuilt.DataVolumeID = cfg.DataVolumeID
	rebuilt.SecretsKeyFile = cfg.SecretsKeyFile
	rebuilt.AdminTokenFile = cfg.AdminTokenFile
	rebuilt.RequireMount = cfg.RequireMount
	rebuilt.TLSCertFile = cfg.TLSCertFile
	rebuilt.TLSKeyFile = cfg.TLSKeyFile
	rebuilt.TLSCACertFile = cfg.TLSCACertFile
	rebuilt.TLSCAKeyFile = cfg.TLSCAKeyFile
	rebuilt.SSHHostKey = cfg.SSHHostKey
	rebuilt.MetricsListen = cfg.MetricsListen
	rebuilt.TLS = cfg.TLS
	rebuilt.SFTP.HostKeyFile = cfg.SFTP.HostKeyFile
	rebuilt.FTP.PublicHost = cfg.FTP.PublicHost
	rebuilt.Metrics.Listen = cfg.Metrics.Listen
	rebuilt.Tenants = cfg.Tenants
	return reflect.DeepEqual(rebuilt, cfg)
}

var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// reservedTenantIDs collide with directories the server keeps under staging/.
var reservedTenantIDs = map[string]bool{"s3-multipart": true}

// ValidTenantID reports whether id is usable as an account ID. IDs become
// directory names on the data disk, so they are restricted to a portable
// character set.
func ValidTenantID(id string) bool {
	return tenantIDPattern.MatchString(id) && !reservedTenantIDs[id] && !strings.Contains(id, "..")
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
	if c.ShutdownGrace < 0 {
		return errors.New("shutdown_grace must not be negative")
	}
	if c.Delivery.MaxAttempts < 1 || c.Delivery.MaxLease < time.Minute || c.Delivery.TombstoneTTL <= 0 || c.Delivery.MaxBatch < 1 || c.Delivery.MaxLongPoll < 0 {
		return errors.New("invalid delivery settings")
	}
	if c.Limits.MaxConnections < 1 || c.Limits.MaxConnectionsPerIP < 1 || c.Limits.HandshakeTimeout <= 0 || c.Limits.IdleTimeout <= 0 || c.Limits.MaxOpenFilesPerSession < 1 || c.Limits.MaxRequestBody < 64<<10 {
		return errors.New("invalid limits settings")
	}
	if c.Download.Listen == "" {
		return errors.New("download.listen is required")
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return errors.New("tls.cert_file and tls.key_file are required")
	}
	if (c.TLS.CACertFile == "") != (c.TLS.CAKeyFile == "") {
		return errors.New("tls.ca_cert_file and tls.ca_key_file must be set together")
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
	return ValidateTenants(c.Tenants, c.SFTP.Enabled, c.FTP.Enabled, c.S3.Enabled)
}

// ValidateTenants checks a set of accounts for completeness and uniqueness.
func ValidateTenants(tenants []Tenant, sftpEnabled, ftpEnabled, s3Enabled bool) error {
	seen := map[string]bool{}
	sftpUsers := map[string]bool{}
	ftpUsers := map[string]bool{}
	s3Access := map[string]bool{}
	s3Buckets := map[string]bool{}
	apiDigests := map[string]bool{}
	for _, t := range tenants {
		if !ValidTenantID(t.ID) || seen[t.ID] {
			return fmt.Errorf("tenant IDs must be unique and use letters, digits, '.', '_' or '-': %q", t.ID)
		}
		seen[t.ID] = true
		if t.Weight < 0 || t.MaxConcurrent < 0 || t.MaxUploadBPS < 0 || t.MaxStoredBytes < 0 || t.MaxAttempts < 0 || t.PublishDelay < 0 {
			return fmt.Errorf("tenant %q has an invalid limit", t.ID)
		}
		if t.Overwrite != "" && t.Overwrite != OverwriteSupersede && t.Overwrite != OverwriteKeep {
			return fmt.Errorf("tenant %q: overwrite must be %q or %q", t.ID, OverwriteSupersede, OverwriteKeep)
		}
		for _, p := range t.HoldPatterns {
			if _, err := path.Match(p, ""); err != nil || strings.Contains(p, "/") {
				return fmt.Errorf("tenant %q: invalid hold pattern %q", t.ID, p)
			}
		}
		_, digestErr := hex.DecodeString(t.APIKeySHA256)
		if digestErr != nil || len(t.APIKeySHA256) != 64 || apiDigests[strings.ToLower(t.APIKeySHA256)] {
			return fmt.Errorf("tenant %q must have a unique SHA-256 API key digest", t.ID)
		}
		apiDigests[strings.ToLower(t.APIKeySHA256)] = true
		if sftpEnabled {
			if t.SFTPUser == "" || sftpUsers[t.SFTPUser] || !(validSecret(t.SFTPPassword, t.SFTPPasswordHash) || len(t.AuthorizedKeys) > 0) {
				return fmt.Errorf("tenant %q must have unique SFTP credentials", t.ID)
			}
			sftpUsers[t.SFTPUser] = true
		}
		if ftpEnabled {
			if t.FTPUser == "" || ftpUsers[t.FTPUser] || !validSecret(t.FTPPassword, t.FTPPasswordHash) {
				return fmt.Errorf("tenant %q must have unique FTP credentials", t.ID)
			}
			ftpUsers[t.FTPUser] = true
		}
		if s3Enabled {
			if t.S3Bucket == "" || t.S3AccessKey == "" || len(t.S3SecretKey) < 16 || s3Access[t.S3AccessKey] || s3Buckets[t.S3Bucket] {
				return fmt.Errorf("tenant %q must have unique S3 bucket and credentials", t.ID)
			}
			s3Access[t.S3AccessKey] = true
			s3Buckets[t.S3Bucket] = true
		}
	}
	return nil
}

func validSecret(plain, hash string) bool {
	if hash != "" {
		return isSecretHash(hash)
	}
	return len(plain) >= 12
}

// LoadAccountsFrom reads an accounts file with this configuration's secrets
// key, without validating it against the rest of the configuration.
func (c Config) LoadAccountsFrom(path string) ([]Tenant, error) {
	return readAccounts(path, c.secretsKeyPath())
}
