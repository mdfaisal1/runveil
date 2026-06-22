package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/mdfaisal1/runveil/pkg/infra"
	"github.com/spf13/cobra"
)

// Mirrors GET /v1/projects/:slug/findings/:id/evidence

type evidenceFinding struct {
	ID            string     `json:"id"`
	Package       string     `json:"package"`
	Version       string     `json:"version"`
	Ecosystem     string     `json:"ecosystem"`
	VulnID        string     `json:"vuln_id"`
	Severity      string     `json:"severity"`
	Reachable     bool       `json:"reachable"`
	EvidenceCount int64      `json:"evidence_count"`
	FirstSeenAt   *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RuntimeState  string     `json:"runtime_state"`
}

type evidenceEvent struct {
	OccurredAt     time.Time `json:"occurred_at"`
	Environment    string    `json:"environment,omitempty"`
	PackageName    string    `json:"package_name"`
	PackageVersion string    `json:"package_version"`
}

type evidenceResponse struct {
	Finding  evidenceFinding `json:"finding"`
	Evidence []evidenceEvent `json:"evidence"`
}

// evidenceListLimit is the API's max page size; we fetch up to this many events
// for the summary and flag when more exist.
const evidenceListLimit = 500

func fetchEvidence(projectSlug, findingID, environment string) (*evidenceResponse, error) {
	base := infra.APIBaseURL()
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", evidenceListLimit))
	if environment != "" {
		q.Set("environment", environment)
	}
	u := fmt.Sprintf("%s/v1/projects/%s/findings/%s/evidence?%s",
		base, url.PathEscape(projectSlug), url.PathEscape(findingID), q.Encode())

	resp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("calling API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API %s returned %s: %s", u, resp.Status, string(body))
	}

	var er evidenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &er, nil
}

var (
	evidenceProject     string
	evidenceFinding_    string
	evidenceFormat      string
	evidenceEnvironment string
)

// NewEvidenceCmd: rv evidence --project <slug> --finding <id> [--format md|json] [--environment <env>]
func NewEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Summarize runtime evidence for a finding (counts by environment, package, day)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if evidenceProject == "" || evidenceFinding_ == "" {
				return fmt.Errorf("--project and --finding are required")
			}

			er, err := fetchEvidence(evidenceProject, evidenceFinding_, evidenceEnvironment)
			if err != nil {
				return err
			}

			switch evidenceFormat {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(er)
			case "md", "":
				return writeEvidenceSummary(os.Stdout, evidenceProject, er)
			default:
				return fmt.Errorf("unknown format %q (use md|json)", evidenceFormat)
			}
		},
	}

	cmd.Flags().StringVar(&evidenceProject, "project", "", "Project slug (required)")
	cmd.Flags().StringVar(&evidenceFinding_, "finding", "", "Finding ID (required)")
	cmd.Flags().StringVar(&evidenceFormat, "format", "md", "Output format: md or json")
	cmd.Flags().StringVar(&evidenceEnvironment, "environment", "", "Filter to one environment (e.g. prod)")
	return cmd
}

// writeEvidenceSummary prints a human-readable summary of evidence counts.
// evidence_events carries only {occurred_at, environment, package, version},
// so we summarize by environment, package@version, and day (no file/function).
func writeEvidenceSummary(w io.Writer, slug string, er *evidenceResponse) error {
	f := er.Finding
	fmt.Fprintf(w, "# Runveil Evidence — %s@%s (%s)\n\n", f.Package, f.Version, f.VulnID)
	fmt.Fprintf(w, "- Project: %s\n", slug)
	fmt.Fprintf(w, "- Severity: %s · Runtime state: %s\n", f.Severity, stateLabel(f.RuntimeState))
	fmt.Fprintf(w, "- Total evidence events: %d\n", f.EvidenceCount)
	fmt.Fprintf(w, "- First seen: %s\n", fmtTime(f.FirstSeenAt))
	fmt.Fprintf(w, "- Last seen:  %s\n\n", fmtTime(f.LastSeenAt))

	if len(er.Evidence) == 0 {
		fmt.Fprintln(w, "_No evidence events recorded — this finding is dormant until the agent observes it executing._")
		return nil
	}

	if int64(len(er.Evidence)) < f.EvidenceCount {
		fmt.Fprintf(w, "> Summarizing the most recent %d of %d events.\n\n", len(er.Evidence), f.EvidenceCount)
	}

	byEnv := map[string]int{}
	byPkg := map[string]int{}
	byDay := map[string]int{}
	for _, e := range er.Evidence {
		env := e.Environment
		if env == "" {
			env = "(unset)"
		}
		byEnv[env]++
		byPkg[fmt.Sprintf("%s@%s", e.PackageName, e.PackageVersion)]++
		byDay[e.OccurredAt.UTC().Format("2006-01-02")]++
	}

	writeCountSection(w, "By environment", byEnv)
	writeCountSection(w, "By package", byPkg)
	writeCountSection(w, "By day (UTC)", byDay)
	return nil
}

// writeCountSection prints a "## title" block with "- key: count" lines,
// sorted by count desc then key asc for stable output.
func writeCountSection(w io.Writer, title string, counts map[string]int) {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	fmt.Fprintf(w, "## %s\n", title)
	for _, it := range items {
		fmt.Fprintf(w, "- %s: %d\n", it.k, it.v)
	}
	fmt.Fprintln(w)
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "–"
	}
	return t.UTC().Format(time.RFC3339)
}

func stateLabel(state string) string {
	switch state {
	case "active":
		return "active ✅"
	case "observed":
		return "observed 🟡"
	case "dormant":
		return "dormant 💤"
	default:
		return state
	}
}
