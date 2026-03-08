package infra

import (
	"os"
	"path/filepath"
	"strings"
)

// APIBaseURL returns the Runveil API base.
// Canonical env: RUNVEIL_API_BASE
// Backward-compatible fallback: RUNVEIL_API_URL
func APIBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_API_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

// APIToken returns the Runveil API token (Bearer/JWT).
// Env: RUNVEIL_API_TOKEN
func APIToken() string {
	return os.Getenv("RUNVEIL_API_TOKEN")
}

// CacheDir returns a writable directory for local cache.
func CacheDir() string {
	if v := os.Getenv("RUNVEIL_CACHE_DIR"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "Runveil")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ".cache/runveil"
	}
	return filepath.Join(home, ".cache", "runveil")
}
