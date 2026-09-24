package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, dir string, serial int64, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	c, k := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	_ = os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return c, k
}

func TestReloadPicksUpRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	first := time.Now().Add(time.Hour).Truncate(time.Second)
	c, k := write(t, dir, 1, first)
	s, err := New(c, k)
	if err != nil {
		t.Fatal(err)
	}
	s.checkEvery = 0
	if !s.NotAfter().Equal(first) {
		t.Fatalf("not after = %v", s.NotAfter())
	}
	second := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	time.Sleep(20 * time.Millisecond)
	write(t, dir, 2, second)
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(c, future, future)
	_ = os.Chtimes(k, future, future)
	cert, err := s.GetCertificate(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("renewed certificate not served: %v", err)
	}
	// A broken pair on disk keeps the last good certificate.
	_ = os.WriteFile(c, []byte("garbage"), 0o644)
	later := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(c, later, later)
	if cert, _ := s.GetCertificate(nil); cert == nil || cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("broken certificate replaced the working one")
	}
}
