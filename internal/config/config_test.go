package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func compactBase() Config {
	cfg := Default()
	cfg.DataDir = "/data"
	cfg.PublicHost = "203.0.113.10"
	cfg.FTP.PublicHost = "203.0.113.10"
	cfg.AccountsFile = "/etc/xsync/accounts.yaml"
	return cfg
}

func TestCompactCompatibleAcceptsOnlyExpressibleConfigs(t *testing.T) {
	if !compactCompatible(compactBase()) {
		t.Fatal("a config that only sets compact-expressible fields should compact")
	}
	cfg := compactBase()
	cfg.Metrics.Listen = "0.0.0.0:9090"
	if !compactCompatible(cfg) {
		t.Fatal("metrics listen is expressible in the compact form")
	}
}

// Anything the compact form cannot represent must force the full format,
// otherwise writing the config back would silently drop the user's setting.
func TestCompactCompatibleRejectsCustomisedFields(t *testing.T) {
	cases := map[string]func(*Config){
		"download listen": func(c *Config) { c.Download.Listen = ":8443" },
		"sftp disabled":   func(c *Config) { c.SFTP.Enabled = false },
		"sftp listen":     func(c *Config) { c.SFTP.Listen = ":22" },
		"ftp disabled":    func(c *Config) { c.FTP.Enabled = false },
		"ftp listen":      func(c *Config) { c.FTP.Listen = ":21" },
		"ftp passive end": func(c *Config) { c.FTP.PassiveEnd = 30200 },
		"ftp close grace": func(c *Config) { c.FTP.CloseGrace = time.Second },
		"s3 listen":       func(c *Config) { c.S3.Listen = ":9001" },
		"capacity soft":   func(c *Config) { c.Capacity.SoftPercent = 60 },
		"capacity runway": func(c *Config) { c.Capacity.TargetRunway = time.Hour },
		"capacity min":    func(c *Config) { c.Capacity.MinFreeBytes = 1 << 30 },
		"max upload bps":  func(c *Config) { c.Capacity.MaxUploadBPS = 1 << 20 },
		"slot wait":       func(c *Config) { c.Capacity.UploadSlotWait = time.Minute },
		"partial ttl":     func(c *Config) { c.PartialTTL = time.Hour },
		"shutdown grace":  func(c *Config) { c.ShutdownGrace = time.Minute },
		"limits":          func(c *Config) { c.Limits.MaxConnections = 10 },
		"idle timeout":    func(c *Config) { c.Limits.IdleTimeout = time.Minute },
		"delivery":        func(c *Config) { c.Delivery.MaxAttempts = 3 },
		"long poll":       func(c *Config) { c.Delivery.MaxLongPoll = time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := compactBase()
			mutate(&cfg)
			if compactCompatible(cfg) {
				t.Error("customised config was treated as compactible; the setting would be lost")
			}
		})
	}
}

func TestWriteKeepsNonCompactSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := Default()
	cfg.DataDir = "/data"
	cfg.AccountsFile = filepath.Join(dir, "accounts.yaml")
	cfg.Delivery.MaxAttempts = 4
	cfg.Tenants = []Tenant{}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "api_key") {
		t.Fatalf("secrets leaked into the main config:\n%s", raw)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Delivery.MaxAttempts != 4 {
		t.Fatalf("delivery setting lost: %+v", loaded.Delivery)
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: /data\ncapacity:\n  sofft_percent: 50\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sofft_percent") {
		t.Fatalf("typo not reported: %v", err)
	}
}

func TestSecretHashing(t *testing.T) {
	h, err := HashSecret("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySecret("correct horse battery", h, "") || VerifySecret("wrong", h, "") {
		t.Fatal("hash verification")
	}
	h2, _ := HashSecret("correct horse battery")
	if h == h2 {
		t.Fatal("hashes are not salted")
	}
	if !VerifySecret("legacy-plain", "", "legacy-plain") || VerifySecret("x", "", "") {
		t.Fatal("legacy plaintext fallback")
	}
}

func TestSecretSealing(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "secrets.key")
	if err := GenerateSecretsKey(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := loadSecretsKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealSecret(key, "s3-secret-value")
	if err != nil || !strings.HasPrefix(sealed, sealedPrefix) || strings.Contains(sealed, "s3-secret-value") {
		t.Fatalf("sealed = %q, %v", sealed, err)
	}
	if plain, err := openSecret(key, sealed); err != nil || plain != "s3-secret-value" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	if _, err := openSecret(nil, sealed); err == nil {
		t.Fatal("sealed secret opened without the key")
	}
	other := make([]byte, 32)
	if _, err := openSecret(other, sealed); err == nil {
		t.Fatal("sealed secret opened with the wrong key")
	}
}

func TestTenantIDValidation(t *testing.T) {
	for _, ok := range []string{"customer-a", "Cust_1", "a.b"} {
		if !ValidTenantID(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "..", "a/b", "a\nb", ".hidden", "s3-multipart", "a..b", strings.Repeat("x", 70)} {
		if ValidTenantID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
