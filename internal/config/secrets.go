package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Protocol passwords are generated 160-bit random secrets, so a salted SHA-256
// is as strong as a slow password hash here and keeps authentication cheap
// enough that it cannot itself be used to exhaust the CPU.
const secretHashPrefix = "sha256:"

// HashSecret returns a salted digest of a generated secret.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(salt, secret...))
	return secretHashPrefix + hex.EncodeToString(salt) + ":" + hex.EncodeToString(sum[:]), nil
}

func isSecretHash(h string) bool {
	_, _, ok := splitSecretHash(h)
	return ok
}

func splitSecretHash(h string) ([]byte, []byte, bool) {
	rest, ok := strings.CutPrefix(h, secretHashPrefix)
	if !ok {
		return nil, nil, false
	}
	saltHex, sumHex, ok := strings.Cut(rest, ":")
	if !ok {
		return nil, nil, false
	}
	salt, err1 := hex.DecodeString(saltHex)
	sum, err2 := hex.DecodeString(sumHex)
	if err1 != nil || err2 != nil || len(salt) < 8 || len(sum) != sha256.Size {
		return nil, nil, false
	}
	return salt, sum, true
}

// VerifySecret checks a presented secret against a stored hash, falling back
// to a legacy plaintext value. Both paths compare in constant time.
func VerifySecret(presented, hash, legacyPlain string) bool {
	if salt, want, ok := splitSecretHash(hash); ok {
		got := sha256.Sum256(append(append([]byte(nil), salt...), presented...))
		return subtle.ConstantTimeCompare(got[:], want) == 1
	}
	if legacyPlain == "" {
		return false
	}
	a := sha256.Sum256([]byte(presented))
	b := sha256.Sum256([]byte(legacyPlain))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

const sealedPrefix = "enc:v1:"

// GenerateSecretsKey writes a new random 256-bit key used to encrypt S3
// secret keys at rest. Keep it outside the configuration backups, for example
// as a Docker secret, to get real protection from it.
func GenerateSecretsKey(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	return WriteFileAtomic(path, []byte(hex.EncodeToString(key)+"\n"), 0o600)
}

func loadSecretsKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secrets key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("secrets key must be 32 bytes of hex")
	}
	return key, nil
}

func sealSecret(key []byte, plain string) (string, error) {
	if key == nil || plain == "" || strings.HasPrefix(plain, sealedPrefix) {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return sealedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

func openSecret(key []byte, stored string) (string, error) {
	rest, ok := strings.CutPrefix(stored, sealedPrefix)
	if !ok {
		return stored, nil
	}
	if key == nil {
		return "", errors.New("S3 secret is encrypted but the secrets key file is missing")
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", errors.New("corrupt encrypted S3 secret")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("corrupt encrypted S3 secret")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("S3 secret does not decrypt with the configured secrets key")
	}
	return string(plain), nil
}
