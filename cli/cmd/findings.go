package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// These mirror the API response from /v1/projects/:slug/findings

type findingView struct {
	Package       string     `json:"package"`
	Version       string     `json:"version"`
	Ecosystem     string     `json:"ecosystem"`
	VulnID        string     `json:"vuln_id"`
	Summary       string     `json:"summary"`
	Severity      string     `json:"severity"`
	Reachable     bool       `json:"reachable"`
	EvidenceCount int64      `json:"evidence_count"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RuntimeState  string     `json:"runtime_state"`
}

type findingsResponse struct {
	ProjectSlug string        `json:"project_slug"`
	Findings    []findingView `json:"findings"`
}

func fetchFindings(projectSlug string) (*findingsResponse, error) {
	apiURL := os.Getenv("RUNVEIL_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	apiURL = strings.TrimRight(apiURL, "/")
	url := fmt.Sprintf("%s/v1/projects/%s/findings", apiURL, projectSlug)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("calling API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API %s returned %s: %s", url, resp.Status, string(body))
	}

	var fr findingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &fr, nil
}

var (
	findingsProject string
	findingsFormat  string
)

// rv findings --project <slug> --format [md|json]
var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Show findings for a project from the Runveil API",
	RunE: func(cmd *cobra.Command, args []string) error {
		if findingsProject == "" {
			return fmt.Errorf("--project is required")
		}

		fr, err := fetchFindings(findingsProject)
		if err != nil {
			return err
		}

		switch findingsFormat {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(fr)
		case "md":
			return writeFindingsMarkdown(os.Stdout, fr)
		default:
			return fmt.Errorf("unknown format %q (use md|json)", findingsFormat)
		}
	},
}

// Markdown renderer: shows runtime state clearly
func writeFindingsMarkdown(w io.Writer, fr *findingsResponse) error {
	fmt.Fprintf(w, "# Runveil Findings — %s\n\n", fr.ProjectSlug)
	if len(fr.Findings) == 0 {
		fmt.Fprintln(w, "_No findings found for this project._")
		return nil
	}

	fmt.Fprintln(w, "| Severity | Runtime | Package | Version | Ecosystem | Vuln ID | Summary | Evidence | Last Seen |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- |")

	for _, f := range fr.Findings {
		runtimeLabel := runtimeLabelFor(f.RuntimeState)

		lastSeen := "-"
		if f.LastSeenAt != nil {
			// Show in UTC, short & readable
			lastSeen = f.LastSeenAt.UTC().Format("2006-01-02 15:04Z")
		}

		fmt.Fprintf(
			w,
			"| %s | %s | %s | %s | %s | %s | %s | %d | %s |\n",
			strings.ToUpper(f.Severity),
			runtimeLabel,
			f.Package,
			f.Version,
			f.Ecosystem,
			f.VulnID,
			f.Summary,
			f.EvidenceCount,
			lastSeen,
		)
	}

	return nil
}

func runtimeLabelFor(state string) string {
	switch state {
	case "active":
		return "✅ active"
	case "observed":
		return "🟡 observed"
	case "dormant":
		return "💤 dormant"
	default:
		return state
	}
}
