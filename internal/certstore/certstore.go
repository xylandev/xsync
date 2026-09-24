// Package certstore serves the TLS certificate from disk and picks up a
// renewed certificate without a restart.
package certstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Store struct {
	certFile, keyFile string
	checkEvery        time.Duration

	mu        sync.RWMutex
	cert      *tls.Certificate
	notAfter  time.Time
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
}

// New loads the certificate pair. Later calls to GetCertificate reload it when
// either file changes on disk.
func New(certFile, keyFile string) (*Store, error) {
	s := &Store{certFile: certFile, keyFile: keyFile, checkEvery: 10 * time.Second}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload reads the certificate pair now.
func (s *Store) Reload() error {
	ci, err1 := os.Stat(s.certFile)
	ki, err2 := os.Stat(s.keyFile)
	if err := errors.Join(err1, err2); err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	cert.Leaf = leaf
	s.mu.Lock()
	s.cert, s.notAfter = &cert, leaf.NotAfter
	s.certMod, s.keyMod, s.lastCheck = ci.ModTime(), ki.ModTime(), time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Store) maybeReload() {
	s.mu.RLock()
	due := time.Since(s.lastCheck) >= s.checkEvery
	certMod, keyMod := s.certMod, s.keyMod
	s.mu.RUnlock()
	if !due {
		return
	}
	s.mu.Lock()
	s.lastCheck = time.Now()
	s.mu.Unlock()
	ci, err1 := os.Stat(s.certFile)
	ki, err2 := os.Stat(s.keyFile)
	if err1 != nil || err2 != nil || (ci.ModTime().Equal(certMod) && ki.ModTime().Equal(keyMod)) {
		return
	}
	// A half-written pair fails to load; keep serving the old one.
	_ = s.Reload()
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *Store) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert, nil
}

// NotAfter returns the expiry of the certificate being served.
func (s *Store) NotAfter() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.notAfter
}

// TLSConfig returns a server configuration that serves the current
// certificate.
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.GetCertificate}
}
