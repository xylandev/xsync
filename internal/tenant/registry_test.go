package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/xylandev/xsync/internal/config"
)

func TestRegistryLookupsAndReplace(t *testing.T) {
	sum := sha256.Sum256([]byte("key-a"))
	r := NewRegistry([]config.Tenant{{ID: "a", SFTPUser: "ua", FTPUser: "fa", S3AccessKey: "AK", S3Bucket: "ba", APIKeySHA256: hex.EncodeToString(sum[:])}})
	s := r.Load()
	if _, ok := s.BySFTPUser("ua"); !ok {
		t.Fatal("sftp lookup")
	}
	if tn, ok := s.ByAPIKey("key-a"); !ok || tn.ID != "a" {
		t.Fatal("api key lookup")
	}
	if _, ok := s.ByAPIKey("wrong"); ok {
		t.Fatal("wrong key accepted")
	}
	notified := 0
	r.Subscribe(func(*Snapshot) { notified++ })
	r.Replace([]config.Tenant{{ID: "a", SFTPUser: "ua", Disabled: true}})
	if notified != 1 {
		t.Fatal("subscriber not notified")
	}
	if _, ok := r.Load().BySFTPUser("ua"); ok {
		t.Fatal("disabled account still authenticates")
	}
	if !s.Active("a") {
		t.Fatal("an old snapshot must stay consistent")
	}
}
