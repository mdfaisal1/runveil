package infra

import (
	"os"
	"path/filepath"
)

// APIBaseURL returns the Keystone API base (for --post).
// Env: KEYSTONE_API_BASE (default: http://localhost:8080)
func APIBaseURL() string {
	if v := os.Getenv("KEYSTONE_API_BASE"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// APIToken returns the Keystone API token (Bearer/JWT).
// Env: KEYSTONE_API_TOKEN (no default)
func APIToken() string {
	return os.Getenv("KEYSTONE_API_TOKEN")
}

// CacheDir returns a writable directory for local cache (OSV, etc.).
// Env: KEYSTONE_CACHE_DIR (default: ~/.cache/keystone or %USERPROFILE%\.cache\keystone)
func CacheDir() string {
	if v := os.Getenv("KEYSTONE_CACHE_DIR"); v != "" {
		return v
	}
	// XDG first
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "keystone")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ".cache/keystone"
	}
	return filepath.Join(home, ".cache", "keystone")
}
