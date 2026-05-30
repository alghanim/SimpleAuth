package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"simpleauth/internal/store"
)

// encPrefix marks a value as AES-256-GCM encrypted (versioned). Values without
// this prefix are treated as legacy plaintext, so existing deployments migrate
// transparently: the secret is re-encrypted on the next save (H4).
const encPrefix = "enc:v1:"

// secretKeyFile is the AES key filename inside the data dir. It lives next to
// the database — NOT inside it — so a database backup does not carry the key
// needed to decrypt the secrets it contains.
const secretKeyFile = "secret.key"

// loadOrCreateSecretKey returns the 32-byte AES-256 key from
// <dataDir>/secret.key, generating it with 0600 perms on first use.
func loadOrCreateSecretKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, secretKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("%s has wrong length %d (want 32)", secretKeyFile, len(data))
		}
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// encryptSecret encrypts plaintext with AES-256-GCM and returns a prefixed,
// base64-encoded string. Empty input returns empty.
func encryptSecret(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if len(key) != 32 {
		return "", errors.New("secret key unavailable")
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// decryptSecret reverses encryptSecret. Values without the prefix are returned
// unchanged (legacy plaintext) so old data keeps working until re-saved.
func decryptSecret(key []byte, value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, encPrefix) {
		return value, nil
	}
	if len(key) != 32 {
		return "", errors.New("secret key unavailable")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, encPrefix))
	if err != nil {
		return "", err
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
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// getLDAPConfigDecrypted reads the LDAP config and returns the bind password in
// plaintext (decrypting at-rest ciphertext, passing through legacy plaintext).
func (h *Handler) getLDAPConfigDecrypted() (*store.LDAPConfig, error) {
	cfg, err := h.store.GetLDAPConfig()
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.BindPassword != "" {
		dec, derr := decryptSecret(h.secretKey, cfg.BindPassword)
		if derr != nil {
			return nil, fmt.Errorf("decrypt ldap bind password: %w", derr)
		}
		cfg.BindPassword = dec
	}
	return cfg, nil
}

// saveLDAPConfigEncrypted encrypts the bind password at rest before persisting.
// It copies the config so the caller's plaintext is not mutated.
func (h *Handler) saveLDAPConfigEncrypted(cfg *store.LDAPConfig) error {
	toSave := *cfg
	if toSave.BindPassword != "" {
		enc, err := encryptSecret(h.secretKey, toSave.BindPassword)
		if err != nil {
			return fmt.Errorf("encrypt ldap bind password: %w", err)
		}
		toSave.BindPassword = enc
	}
	return h.store.SaveLDAPConfig(&toSave)
}
