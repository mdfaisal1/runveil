package infra

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
)

// FileCfg is the on-disk CLI config (~/.runveil/config.yaml). It lets the CLI
// work without exporting RUNVEIL_* env vars on every invocation. Precedence is
// always flag > env > file > built-in default — this file is the lowest rung
// above the defaults, so an explicit env var or flag still wins.
type FileCfg struct {
	APIBase string `yaml:"api_base,omitempty"`
	Token   string `yaml:"token,omitempty"`
	Org     string `yaml:"org,omitempty"`
	Project string `yaml:"project,omitempty"`
}

var (
	fileCfgOnce  sync.Once
	fileCfgCache FileCfg
)

// ConfigPath returns the CLI config file path: $RUNVEIL_CONFIG if set, else
// $XDG_CONFIG_HOME/runveil/config.yaml, else ~/.runveil/config.yaml.
func ConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_CONFIG")); v != "" {
		return v
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "runveil", "config.yaml")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return filepath.Join(".runveil", "config.yaml")
	}
	return filepath.Join(home, ".runveil", "config.yaml")
}

// FileConfig returns the parsed config file, cached for the process. A missing
// or unreadable file yields a zero value (treated as "nothing set").
func FileConfig() FileCfg {
	fileCfgOnce.Do(func() {
		b, err := os.ReadFile(ConfigPath())
		if err != nil {
			return // missing/unreadable → zero config
		}
		var c FileCfg
		if yaml.Unmarshal(b, &c) == nil {
			fileCfgCache = c
		}
	})
	return fileCfgCache
}

// SaveFileConfig writes the config file with 0600 perms (it holds an API token).
// NOTE: on Windows file-mode bits are advisory; ACLs govern real access.
func SaveFileConfig(c FileCfg) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ConfigOrg / ConfigProject expose the file defaults used as the lowest-priority
// fallback for --org / --project flags in CLI commands.
func ConfigOrg() string     { return strings.TrimSpace(FileConfig().Org) }
func ConfigProject() string { return strings.TrimSpace(FileConfig().Project) }
