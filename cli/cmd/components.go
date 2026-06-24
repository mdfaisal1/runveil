package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mdfaisal1/runveil/pkg/infra"
	"github.com/spf13/cobra"
)

// componentSummary mirrors the API's ComponentView (services/api/components.go).
type componentSummary struct {
	Key            string     `json:"key"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	FindingCount   int        `json:"finding_count"`
	ReachableCount int        `json:"reachable_count"`
	MaxSeverity    string     `json:"max_severity"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
}

type componentsListResponse struct {
	ProjectSlug string             `json:"project_slug"`
	Components  []componentSummary `json:"components"`
}

// NewComponentsCmd is the parent for component (service) management. Components
// are manifest-declared: register one here before attaching scans to it with
// `runveil scan --component <key> --post`. These talk to the API (not Postgres
// directly) so they work against a deployed Runveil.
func NewComponentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "components",
		Short: "Register and list a project's components (services)",
	}
	cmd.AddCommand(newComponentsCreateCmd())
	cmd.AddCommand(newComponentsListCmd())
	return cmd
}

func newComponentsCreateCmd() *cobra.Command {
	var (
		project string
		key     string
		name    string
		kind    string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register a component so scans can attach to it",
		RunE: func(cmd *cobra.Command, args []string) error {
			project = strings.TrimSpace(project)
			if project == "" {
				project = infra.ConfigProject()
			}
			key = strings.TrimSpace(key)
			if project == "" || key == "" {
				return fmt.Errorf("--project and --key are required")
			}

			infra.MustLoad()
			payload, _ := json.Marshal(map[string]string{"key": key, "name": name, "kind": kind})

			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			url := fmt.Sprintf("%s/v1/projects/%s/components", infra.APIBaseURL(), project)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			if tok := infra.APIToken(); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("creating component: %w", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == http.StatusConflict {
				return fmt.Errorf("component %q already exists for project %q", key, project)
			}
			if resp.StatusCode == http.StatusNotFound {
				return fmt.Errorf("project %q not found — create it first", project)
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("create component failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var cv componentSummary
			_ = json.Unmarshal(body, &cv)
			fmt.Printf("✅ Component registered: %s (%s) in project %s\n", cv.Key, cv.Kind, project)
			fmt.Printf("   Attach scans with:  runveil scan <lockfile> --post --project %s --component %s\n", project, cv.Key)
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project slug (required)")
	cmd.Flags().StringVar(&key, "key", "", "component key, e.g. api / web (required)")
	cmd.Flags().StringVar(&name, "name", "", "human-readable name (defaults to key)")
	cmd.Flags().StringVar(&kind, "kind", "service", "component kind: service|app|library")
	return cmd
}

func newComponentsListCmd() *cobra.Command {
	var (
		project string
		format  string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's components with a rollup of their latest scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			project = strings.TrimSpace(project)
			if project == "" {
				project = infra.ConfigProject()
			}
			if project == "" {
				return fmt.Errorf("--project is required")
			}

			infra.MustLoad()
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			url := fmt.Sprintf("%s/v1/projects/%s/components", infra.APIBaseURL(), project)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			if tok := infra.APIToken(); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("listing components: %w", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("list components failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var out componentsListResponse
			if err := json.Unmarshal(body, &out); err != nil {
				return fmt.Errorf("decoding response: %w", err)
			}

			if format == "json" {
				os.Stdout.Write(body)
				fmt.Println()
				return nil
			}

			if len(out.Components) == 0 {
				fmt.Printf("No components registered for %s yet. Create one with: runveil components create --project %s --key <key>\n", project, project)
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tKIND\tFINDINGS\tREACHABLE\tMAX SEV\tLAST SCANNED")
			for _, c := range out.Components {
				last := "—"
				if c.LastScannedAt != nil {
					last = c.LastScannedAt.Format("2006-01-02 15:04")
				}
				sev := c.MaxSeverity
				if sev == "" {
					sev = "—"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", c.Key, c.Kind, c.FindingCount, c.ReachableCount, sev, last)
			}
			w.Flush()
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project slug (required)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}
