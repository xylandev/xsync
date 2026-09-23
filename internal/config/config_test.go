package config

import (
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
}

// Anything the compact form cannot represent must force the full format,
// otherwise writing the config back would silently drop the user's setting.
func TestCompactCompatibleRejectsCustomisedFields(t *testing.T) {
	cases := map[string]func(*Config){
		"download listen": func(c *Config) { c.Download.Listen = ":8443" },
		"metrics listen":  func(c *Config) { c.Metrics.Listen = "0.0.0.0:9090" },
		"sftp disabled":   func(c *Config) { c.SFTP.Enabled = false },
		"sftp listen":     func(c *Config) { c.SFTP.Listen = ":22" },
		"ftp disabled":    func(c *Config) { c.FTP.Enabled = false },
		"ftp listen":      func(c *Config) { c.FTP.Listen = ":21" },
		"ftp passive end": func(c *Config) { c.FTP.PassiveEnd = 30200 },
		"s3 listen":       func(c *Config) { c.S3.Listen = ":9001" },
		"capacity soft":   func(c *Config) { c.Capacity.SoftPercent = 60 },
		"capacity runway": func(c *Config) { c.Capacity.TargetRunway = time.Hour },
		"capacity min":    func(c *Config) { c.Capacity.MinFreeBytes = 1 << 30 },
		"max upload bps":  func(c *Config) { c.Capacity.MaxUploadBPS = 1 << 20 },
		"partial ttl":     func(c *Config) { c.PartialTTL = time.Hour },
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
