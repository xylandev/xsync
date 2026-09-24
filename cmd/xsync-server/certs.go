package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/config"
	"golang.org/x/crypto/ssh"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 397 * 24 * time.Hour
)

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func writePEM(name, typ string, der []byte, perm os.FileMode) error {
	return config.WriteFileAtomic(name, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), perm)
}

func writeKey(name string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(name, "PRIVATE KEY", der, 0o600)
}

// generateCA creates the long-lived CA that connection bundles trust.
func generateCA(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "xsync CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(caValidity),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:     true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeKey(keyFile, key); err != nil {
		return err
	}
	return writePEM(certFile, "CERTIFICATE", der, 0o644)
}

func loadCA(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("CA certificate file contains no certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("CA key file contains no key")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("CA key cannot sign")
	}
	return ca, signer, nil
}

// issueLeaf signs a short-lived serving certificate for the given addresses.
func issueLeaf(caCert, caKey, certFile, keyFile string, ips []net.IP, names []string, validity time.Duration) error {
	ca, signer, err := loadCA(caCert, caKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	cn := "xsync"
	if len(names) > 0 {
		cn = names[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}
	tmpl := x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ips, DNSNames: names, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, signer)
	if err != nil {
		return err
	}
	// Key first: a reader that sees a new certificate with the old key fails
	// to load the pair and keeps serving the previous one.
	if err := writeKey(keyFile, key); err != nil {
		return err
	}
	return writePEM(certFile, "CERTIFICATE", der, 0o644)
}

func readCert(name string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no certificate in " + name)
	}
	return x509.ParseCertificate(block.Bytes)
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
	return config.WriteFileAtomic(name, pem.EncodeToMemory(block), 0o600)
}

func parseAddresses(ipText, dns string) ([]net.IP, []string, error) {
	var ips []net.IP
	for _, s := range strings.Split(ipText, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", s)
		}
		ips = append(ips, ip)
	}
	var names []string
	for _, s := range strings.Split(dns, ",") {
		if s = strings.TrimSpace(s); s != "" {
			names = append(names, s)
		}
	}
	if len(ips) == 0 && len(names) == 0 {
		return nil, nil, errors.New("at least one IP address or DNS name is required")
	}
	return ips, names, nil
}

func certCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xsync-server cert <renew|info> [options]")
	}
	switch args[0] {
	case "renew":
		return certRenewCommand(args[1:])
	case "info":
		return certInfoCommand(args[1:])
	}
	return fmt.Errorf("unknown cert command %q", args[0])
}

// certRenewCommand issues a new serving certificate from the CA. Bundles pin
// the CA, so no client needs to change. A deployment from before the CA split
// can move to one with --new-ca, after which bundles must be reissued.
func certRenewCommand(args []string) error {
	fs := flag.NewFlagSet("cert renew", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	ipText := fs.String("advertise-ip", "", "IP addresses for the certificate (default: keep the current ones)")
	dns := fs.String("dns", "", "DNS names for the certificate (default: keep the current ones)")
	days := fs.Int("days", 397, "validity of the serving certificate in days")
	newCA := fs.Bool("new-ca", false, "create a CA for a deployment that predates it (bundles must be reissued)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	current, _ := readCert(cfg.TLS.CertFile)
	ips, names := []net.IP(nil), []string(nil)
	if *ipText != "" || *dns != "" {
		if ips, names, err = parseAddresses(*ipText, *dns); err != nil {
			return err
		}
	} else if current != nil {
		ips, names = current.IPAddresses, current.DNSNames
	} else {
		return errors.New("cannot read the current certificate; pass --advertise-ip or --dns")
	}
	if cfg.TLS.CACertFile == "" {
		if !*newCA {
			return errors.New("this deployment has no CA (its certificate is self-signed); run 'cert renew --new-ca' and then reissue every connection bundle with 'account rotate'")
		}
		dir := filepath.Dir(*configPath)
		caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
		if err := generateCA(caCert, caKey); err != nil {
			return err
		}
		if err := config.Update(*configPath, func(c *config.Config) error {
			c.TLSCACertFile, c.TLSCAKeyFile = caCert, caKey
			c.TLS.CACertFile, c.TLS.CAKeyFile = caCert, caKey
			return nil
		}); err != nil {
			return err
		}
		cfg.TLS.CACertFile, cfg.TLS.CAKeyFile = caCert, caKey
		fmt.Println("created a new CA; existing connection bundles trust the old certificate and must be reissued with 'xsync-server account rotate --id <account>'")
	}
	if err := issueLeaf(cfg.TLS.CACertFile, cfg.TLS.CAKeyFile, cfg.TLS.CertFile, cfg.TLS.KeyFile, ips, names, time.Duration(*days)*24*time.Hour); err != nil {
		return err
	}
	leaf, _ := readCert(cfg.TLS.CertFile)
	fmt.Printf("issued a new serving certificate valid until %s\n", leaf.NotAfter.Format(time.RFC3339))
	fmt.Println("the running server picks it up within a few seconds; no restart or bundle change is needed")
	return nil
}

func certInfoCommand(args []string) error {
	fs := flag.NewFlagSet("cert info", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	show := func(label, name string) {
		c, err := readCert(name)
		if err != nil {
			fmt.Printf("%s: %v\n", label, err)
			return
		}
		fmt.Printf("%s: %s\n  subject: %s\n  not after: %s (%d days left)\n  ips: %v\n  dns: %v\n", label, name, c.Subject.CommonName, c.NotAfter.Format(time.RFC3339), int(time.Until(c.NotAfter).Hours()/24), c.IPAddresses, c.DNSNames)
	}
	show("serving certificate", cfg.TLS.CertFile)
	if cfg.TLS.CACertFile != "" {
		show("CA", cfg.TLS.CACertFile)
	} else {
		fmt.Println("CA: none (legacy self-signed certificate; see 'cert renew --new-ca')")
	}
	return nil
}
