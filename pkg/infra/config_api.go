package infra

import (
	"os"
	"path/filepath"
)

// APIBaseURL returns the Runveil API base (for --post).
// Env: RUNVEIL_API_BASE (default: http://localhost:8080)
func APIBaseURL() string {
	if v := os.Getenv("RUNVEIL_API_BASE"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// APIToken returns the Runveil API token (Bearer/JWT).
// Env: RUNVEIL_API_TOKEN (no default)
func APIToken() string {
	return os.Getenv("RUNVEIL_API_TOKEN")
}

// CacheDir returns a writable directory for local cache (OSV, etc.).
// Env: RUNVEIL_CACHE_DIR (default: ~/.cache/Runveil or %USERPROFILE%\.cache\Runveil)
func CacheDir() string {
	if v := os.Getenv("RUNVEIL_CACHE_DIR"); v != "" {
		return v
	}
	// XDG first
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "Runveil")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ".cache/runveil"
	}
	return filepath.Join(home, ".cache", "runveil")
}
