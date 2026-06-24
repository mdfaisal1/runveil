package cmd

import (
	"fmt"
	"strings"

	"github.com/mdfaisal1/runveil/pkg/infra"
	"github.com/spf13/cobra"
)

// configKeys are the settable fields in ~/.runveil/config.yaml.
var configKeys = map[string]bool{"api_base": true, "token": true, "org": true, "project": true}

// NewConfigCmd manages the CLI's on-disk config so you don't have to export
// RUNVEIL_* on every invocation. Env vars and flags still override the file.
func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI config (~/.runveil/config.yaml)",
		Long: "Persist api_base / token / org / project so the CLI works without\n" +
			"exporting env vars. Precedence is always flag > env > file > default.",
	}
	cmd.AddCommand(newConfigSetCmd(), newConfigGetCmd(), newConfigViewCmd(), newConfigPathCmd())
	return cmd
}

func get(c infra.FileCfg, key string) string {
	switch key {
	case "api_base":
		return c.APIBase
	case "token":
		return c.Token
	case "org":
		return c.Org
	case "project":
		return c.Project
	}
	return ""
}

func set(c *infra.FileCfg, key, val string) {
	switch key {
	case "api_base":
		c.APIBase = val
	case "token":
		c.Token = val
	case "org":
		c.Org = val
	case "project":
		c.Project = val
	}
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value (key: api_base|token|org|project)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			if !configKeys[key] {
				return fmt.Errorf("unknown key %q (use api_base|token|org|project)", key)
			}
			c := infra.FileConfig()
			set(&c, key, args[1])
			if err := infra.SaveFileConfig(c); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Printf("✅ set %s in %s\n", key, infra.ConfigPath())
			return nil
		},
	}
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print a single config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			if !configKeys[key] {
				return fmt.Errorf("unknown key %q (use api_base|token|org|project)", key)
			}
			fmt.Println(get(infra.FileConfig(), key))
			return nil
		},
	}
}

func newConfigViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "Show the effective config (token masked)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := infra.FileConfig()
			fmt.Printf("path:     %s\n", infra.ConfigPath())
			fmt.Printf("api_base: %s\n", firstNonEmpty(c.APIBase, "(default) "+infra.APIBaseURL()))
			fmt.Printf("token:    %s\n", maskToken(c.Token))
			fmt.Printf("org:      %s\n", firstNonEmpty(c.Org, "—"))
			fmt.Printf("project:  %s\n", firstNonEmpty(c.Project, "—"))
			return nil
		},
	}
}

func newConfigPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the config file path",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(infra.ConfigPath())
			return nil
		},
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func maskToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "—"
	}
	if len(t) <= 8 {
		return "****"
	}
	return t[:7] + "…(masked)"
}
