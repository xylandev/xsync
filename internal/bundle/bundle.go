package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xylandev/xsync/internal/config"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const Version = 1

type Secrets struct {
	APIKey       string
	SFTPPassword string
	FTPPassword  string
	S3Secret     string
}

// Document is the portable, account-scoped connection bundle handed to users.
// It intentionally contains public trust material, but never server private keys.
type Document struct {
	Version  int              `yaml:"version"`
	Account  string           `yaml:"account"`
	Download Download         `yaml:"download"`
	SFTP     SFTP             `yaml:"sftp"`
	FTPS     FTPS             `yaml:"ftps"`
	S3       S3               `yaml:"s3"`
	Security SecurityMaterial `yaml:"security"`
}

type Download struct {
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
}

type SFTP struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	HostKeyFingerprint string `yaml:"host_key_sha256"`
}

type FTPS struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TLSMode  string `yaml:"tls_mode"`
}

type S3 struct {
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Region    string `yaml:"region"`
}

type SecurityMaterial struct {
	TLSCAPEM                  string `yaml:"tls_ca_pem"`
	TLSCertificateFingerprint string `yaml:"tls_certificate_sha256"`
}

func New(cfg config.Config, tenant config.Tenant, secrets Secrets) (Document, error) {
	host := strings.TrimSpace(cfg.PublicHost)
	if host == "" {
		host = strings.TrimSpace(cfg.FTP.PublicHost)
	}
	if host == "" {
		return Document{}, errors.New("public_host is required to generate a client connection bundle")
	}
	caPEM, certFingerprint, err := certificateMaterial(cfg.TLS.CertFile)
	if err != nil {
		return Document{}, err
	}
	sshFingerprint, err := sshHostKeyFingerprint(cfg.SFTP.HostKeyFile)
	if err != nil {
		return Document{}, err
	}
	downloadPort, err := listenPort(cfg.Download.Listen)
	if err != nil {
		return Document{}, fmt.Errorf("download port: %w", err)
	}
	sftpPort, err := listenPort(cfg.SFTP.Listen)
	if err != nil {
		return Document{}, fmt.Errorf("SFTP port: %w", err)
	}
	ftpPort, err := listenPort(cfg.FTP.Listen)
	if err != nil {
		return Document{}, fmt.Errorf("FTPS port: %w", err)
	}
	s3Port, err := listenPort(cfg.S3.Listen)
	if err != nil {
		return Document{}, fmt.Errorf("S3 port: %w", err)
	}
	return Document{
		Version: Version,
		Account: tenant.ID,
		Download: Download{
			Endpoint: "https://" + net.JoinHostPort(host, strconv.Itoa(downloadPort)),
			APIKey:   secrets.APIKey,
		},
		SFTP: SFTP{
			Host:               host,
			Port:               sftpPort,
			Username:           tenant.SFTPUser,
			Password:           secrets.SFTPPassword,
			HostKeyFingerprint: sshFingerprint,
		},
		FTPS: FTPS{
			Host: host, Port: ftpPort, Username: tenant.FTPUser,
			Password: secrets.FTPPassword, TLSMode: "explicit",
		},
		S3: S3{
			Endpoint: "https://" + net.JoinHostPort(host, strconv.Itoa(s3Port)),
			Bucket:   tenant.S3Bucket, AccessKey: tenant.S3AccessKey,
			SecretKey: secrets.S3Secret, Region: "us-east-1",
		},
		Security: SecurityMaterial{
			TLSCAPEM: caPEM, TLSCertificateFingerprint: certFingerprint,
		},
	}, nil
}

func Write(path string, doc Document, replace bool) error {
	raw, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xsync-client-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(raw)
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
	if replace {
		if err = os.Rename(tmpName, path); err != nil {
			return err
		}
	} else {
		// Link publishes without replacing an existing bundle, including when
		// multiple account-add processes race for the same output path.
		if err = os.Link(tmpName, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("connection bundle already exists: %s", path)
			}
			return err
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func DefaultPath(configPath, account string) string {
	var name strings.Builder
	for _, r := range account {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			name.WriteRune(r)
		} else {
			name.WriteByte('_')
		}
	}
	clean := strings.Trim(name.String(), ".")
	if clean == "" {
		clean = "account"
	}
	return filepath.Join(filepath.Dir(configPath), "client-configs", clean+".yaml")
}

func listenPort(address string) (int, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid listen address %q", address)
	}
	return port, nil
}

func certificateMaterial(path string) (string, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read TLS certificate: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", "", errors.New("TLS certificate file contains no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse TLS certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

func sshHostKeyFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read SSH host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse SSH host key: %w", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}
