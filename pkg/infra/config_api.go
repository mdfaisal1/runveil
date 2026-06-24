package infra

import (
	"os"
	"path/filepath"
	"strings"
)

// APIBaseURL returns the Runveil API base. Precedence: env > config file >
// built-in default (an empty env var falls through, never shadows the file).
//
//	env: RUNVEIL_API_BASE (canonical) / RUNVEIL_API_URL (legacy)
//	file: api_base in ~/.runveil/config.yaml
func APIBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_API_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(FileConfig().APIBase); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

// APIToken returns the Runveil API token. Precedence: env > config file.
//
//	env: RUNVEIL_API_TOKEN
//	file: token in ~/.runveil/config.yaml
func APIToken() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_API_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(FileConfig().Token)
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
