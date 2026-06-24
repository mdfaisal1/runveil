package infra

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// SessionCookieName is the cookie that carries the opaque session token in the
// browser. HttpOnly + SameSite are set when the cookie is issued (see the API).
const SessionCookieName = "rv_session"

// GenerateSessionToken mints an opaque session token for a browser session.
// It returns the plaintext (set as the cookie value, shown to the browser once)
// and the hex SHA-256 hash (the only form persisted in the sessions table).
//
// Like API keys, we never store the plaintext — a leaked sessions table cannot
// be replayed as cookies.
func GenerateSessionToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(buf)
	hash = HashSessionToken(plaintext)
	return plaintext, hash, nil
}

// HashSessionToken returns the hex-encoded SHA-256 of a session token. The API
// hashes the incoming cookie value and looks it up by hash.
func HashSessionToken(plaintext string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plaintext)))
	return hex.EncodeToString(sum[:])
}

// HashPassword returns a bcrypt hash suitable for storing in users.password_hash.
func HashPassword(plaintext string) (string, error) {
	if len(plaintext) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// VerifyPassword reports whether plaintext matches a stored bcrypt hash.
func VerifyPassword(hash, plaintext string) bool {
	if hash == "" {
		return false // SSO-only account, no local password
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}
