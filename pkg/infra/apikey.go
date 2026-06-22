package infra

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// APIKeyPrefix is the literal prefix on every minted key, so a leaked key is
// recognizable as a Runveil credential.
const APIKeyPrefix = "rv_"

// GenerateAPIKey mints a new API key. It returns:
//   - plaintext: the full key ("rv_<base64url>"), shown to the operator ONCE
//   - prefix:    a short display prefix (e.g. "rv_AbC3") stored for identification
//   - hash:      sha256(plaintext) in hex, the only form persisted
//
// The random component is 32 bytes (256 bits) of crypto/rand.
func GenerateAPIKey() (plaintext, prefix, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("generate api key: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(buf)
	plaintext = APIKeyPrefix + body
	hash = HashAPIKey(plaintext)

	// Display prefix: "rv_" + first 4 chars of the random body.
	n := 4
	if len(body) < n {
		n = len(body)
	}
	prefix = APIKeyPrefix + body[:n]
	return plaintext, prefix, hash, nil
}

// HashAPIKey returns the hex-encoded SHA-256 of a plaintext key. Both the CLI
// (when minting) and the API (when verifying) must produce the same value, so
// the input is trimmed but otherwise hashed verbatim.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plaintext)))
	return hex.EncodeToString(sum[:])
}
