package infra

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// Reversible-secret encryption at rest (AES-256-GCM), used for values we must
// later hand back to a third party — currently only oidc_providers.client_secret.
// (API keys, sessions, and runtime tokens are hashed verifiers, NOT reversible
// secrets, and are intentionally out of scope here.)
//
// The key is sha256(RUNVEIL_SECRET_KEY) — hashing the passphrase to exactly 32
// bytes avoids all key-length/encoding ambiguity. Stored ciphertext is tagged
// "enc:v1:"; untagged values are treated as legacy plaintext so existing rows
// keep working and can be re-encrypted on next write.

const encPrefix = "enc:v1:"

var warnNoKeyOnce sync.Once

func secretKey() ([]byte, bool) {
	v := strings.TrimSpace(os.Getenv("RUNVEIL_SECRET_KEY"))
	if v == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(v))
	return sum[:], true
}

// EncryptSecret returns an "enc:v1:"-tagged ciphertext when RUNVEIL_SECRET_KEY is
// set. When it is NOT set we store plaintext (dev convenience) but warn loudly —
// production MUST set the key, or secrets sit in the clear (the very thing this
// guards against). The warning fires once per process.
func EncryptSecret(plaintext string) (string, error) {
	key, ok := secretKey()
	if !ok {
		warnNoKeyOnce.Do(func() {
			log.Printf("WARNING: RUNVEIL_SECRET_KEY is not set — reversible secrets (e.g. OIDC client secrets) are stored in PLAINTEXT. Set RUNVEIL_SECRET_KEY in production.")
		})
		return plaintext, nil
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
	return encPrefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

// DecryptSecret reverses EncryptSecret. Untagged input is returned as-is (legacy
// plaintext). A tagged value with no/!wrong key returns an error (GCM auth
// failure) rather than garbage — callers surface that as a clean 5xx.
func DecryptSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, nil // legacy plaintext
	}
	key, ok := secretKey()
	if !ok {
		return "", errors.New("RUNVEIL_SECRET_KEY is required to decrypt a stored secret")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
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
		return "", errors.New("secret decryption failed (wrong or rotated RUNVEIL_SECRET_KEY?)")
	}
	return string(pt), nil
}
