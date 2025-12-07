package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"runveil/pkg/infra"
)

/********** report model **********/

type severity string

const (
	severityNone     severity = "none"
	severityLow      severity = "low"
	severityMedium   severity = "medium"
	severityHigh     severity = "high"
	severityCritical severity = "critical"
)

func sevRank(s severity) int {
	switch s {
	case severityLow:
		return 1
	case severityMedium:
		return 2
	case severityHigh:
		return 3
	case severityCritical:
		return 4
	default:
		return 0
	}
}

type finding struct {
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	VulnID    string   `json:"vuln_id"`
	Summary   string   `json:"summary"`
	Severity  severity `json:"severity"`
}

type report struct {
	ProjectSlug string    `json:"project_slug"`
	Total       int       `json:"total"`
	Findings    []finding `json:"findings"`
	MaxSeverity severity  `json:"max_severity"`
	GeneratedAt string    `json:"generated_at"`
}

/********** flags **********/

var (
	flagPost    bool
	flagProject string
	flagFormat  string // json|md
	flagOutPath string // file path for report
	flagFailOn  string // none|low|medium|high|critical
)

/********** command **********/

var scanCmd = &cobra.Command{
	Use:   "scan [path-to-package-lock.json]",
	Short: "Scan a Node.js project (package-lock.json) for vulnerabilities using OSV",
	Long:  "Parses package-lock.json (v2/v3 style), queries the OSV API per dependency, and prints only vulnerable packages.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// validate format
		if flagFormat != "json" && flagFormat != "md" {
			fmt.Println("❌ --format must be 'json' or 'md'")
			os.Exit(1)
		}
		// validate fail-on
		threshold, err := parseFailOn(flagFailOn)
		if err != nil {
			fmt.Println("❌", err)
			os.Exit(1)
		}

		lockfilePath := filepath.Clean(args[0])

		data, err := os.ReadFile(lockfilePath)
		if err != nil {
			fmt.Println("❌ Error reading lockfile:", err)
			os.Exit(1)
		}

		var lock map[string]any
		if err := json.Unmarshal(data, &lock); err != nil {
			fmt.Println("❌ Invalid JSON:", err)
			os.Exit(1)
		}

		// Extract deps from "packages" block (npm lockfile v2/v3).
		deps := extractNpmPackages(lock)
		if len(deps) == 0 {
			fmt.Println("⚠️  No dependencies found in lockfile (expected npm lockfile v2/v3).")
			return
		}

		fmt.Printf("🔎 Scanning %d packages from: %s\n", len(deps), lockfilePath)

		ctx := cmd.Context()
		osvClient := infra.NewOSV()

		vulnCount := 0
		findings := make([]finding, 0, 64)
		maxSeen := severityNone

		for _, d := range deps {
			if d.name == "" || d.version == "" {
				continue
			}
			res, err := osvClient.Query(ctx, "npm", d.name, d.version)
			if err != nil {
				fmt.Printf("  ❌ %s@%s → OSV query failed: %v\n", d.name, d.version, err)
				continue
			}
			if len(res.Vulns) == 0 {
				continue
			}

			vulnCount += len(res.Vulns)
			fmt.Printf("  🚨 %s@%s — %d vuln(s)\n", d.name, d.version, len(res.Vulns))
			for _, v := range res.Vulns {
				s := strings.Split(strings.TrimSpace(v.Summary), "\n")[0]
				if len(s) > 110 {
					s = s[:110] + "…"
				}
				sev := mapCVSS(v.Severity)
				if sevRank(sev) > sevRank(maxSeen) {
					maxSeen = sev
				}
				fmt.Printf("     • %s — %s\n", v.ID, s)

				findings = append(findings, finding{
					Package:   d.name,
					Version:   d.version,
					Ecosystem: "npm",
					VulnID:    v.ID,
					Summary:   s,
					Severity:  sev,
				})
			}
		}

		if vulnCount == 0 {
			fmt.Println("✅ No known vulnerabilities found for the packages in this lockfile (per OSV).")
		}

		// Build report
		rep := report{
			ProjectSlug: flagProject,
			Total:       len(findings),
			Findings:    findings,
			MaxSeverity: maxSeen,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}

		// Always produce JSON (for --post) + optionally a formatted view
		reportJSON, _ := json.MarshalIndent(rep, "", "  ")
		var outBytes []byte
		switch flagFormat {
		case "json":
			outBytes = reportJSON
		case "md":
			outBytes = renderMarkdown(rep)
		}

		// Write to file or stdout
		if flagOutPath != "" {
			if err := os.MkdirAll(filepath.Dir(flagOutPath), 0o755); err != nil {
				fmt.Println("❌ create dir:", err)
				os.Exit(1)
			}
			if err := os.WriteFile(flagOutPath, outBytes, 0o644); err != nil {
				fmt.Println("❌ write report:", err)
				os.Exit(1)
			}
			fmt.Printf("📝 Report written to %s (%s)\n", flagOutPath, flagFormat)
		} else {
			os.Stdout.Write(outBytes)
			if flagFormat == "md" {
				fmt.Println()
			}
		}

		// If --post is set, send JSON to API
		if flagPost {
			if flagProject == "" {
				fmt.Println("❌ --project is required when using --post")
				os.Exit(1)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()
			if err := infra.PostScan(ctx, flagProject, reportJSON); err != nil {
				fmt.Printf("❌ post failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("📤 Posted scan to Runveil API.")
		}

		// 🔥 NEW: runtime summary (if a project slug is provided)
		if flagProject != "" {
			maybePrintRuntimeSummary(flagProject)
		}

		// CI/CD gating
		if shouldFail(maxSeen, threshold) {
			fmt.Printf("⛔ Policy fail: max severity %s ≥ --fail-on %s\n", strings.ToUpper(string(maxSeen)), strings.ToUpper(string(threshold)))
			os.Exit(3) // dedicated exit code for policy violation
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Existing flags
	scanCmd.Flags().BoolVar(&flagPost, "post", false, "Send the generated report to Runveil API")
	scanCmd.Flags().StringVar(&flagProject, "project", "", "Project slug (required with --post)")

	// Formatting
	scanCmd.Flags().StringVar(&flagFormat, "format", "json", "Report format: json|md")
	scanCmd.Flags().StringVar(&flagOutPath, "out", "", "Write report to this file (otherwise stdout)")

	// CI gating
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "none", "Fail build if max severity meets/exceeds this level: none|low|medium|high|critical")
}

/********** helpers already used **********/

type dep struct {
	name    string
	version string
}

func extractNpmPackages(lock map[string]any) []dep {
	packagesAny, ok := lock["packages"]
	if !ok {
		return nil
	}
	packages, ok := packagesAny.(map[string]any)
	if !ok {
		return nil
	}

	out := make([]dep, 0, len(packages))
	for k, v := range packages {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		ver, _ := entry["version"].(string)

		// Root package entry has key "" — skip it (no module name)
		if k == "" {
			continue
		}

		name := strings.TrimPrefix(k, "node_modules/")
		// Scoped packages appear as "node_modules/@scope/pkg" → keep as "@scope/pkg"
		if strings.HasPrefix(name, "@") && strings.Count(name, "/") >= 1 {
			parts := strings.SplitN(name, "/", 2)
			if len(parts) == 2 {
				name = parts[0] + "/" + parts[1]
			}
		} else if i := strings.Index(name, "/"); i >= 0 && !strings.HasPrefix(name, "@") {
			// For paths like "node_modules/foo/bar" (rare), keep only the first segment
			name = name[:i]
		}

		out = append(out, dep{name: name, version: ver})
	}
	return out
}

func renderMarkdown(rep report) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Runveil Scan Report — %s\n\n", safe(rep.ProjectSlug, "N/A"))
	fmt.Fprintf(&b, "**Findings:** %d  •  **Max Severity:** %s  •  **Generated:** %s UTC\n\n",
		rep.Total, strings.ToUpper(string(rep.MaxSeverity)), rep.GeneratedAt)
	if rep.Total == 0 {
		b.WriteString("_No vulnerabilities found._\n")
		return []byte(b.String())
	}
	b.WriteString("| Severity | Package | Version | Ecosystem | Vuln ID | Summary |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			strings.ToUpper(string(f.Severity)),
			escapeMD(f.Package), escapeMD(f.Version), escapeMD(f.Ecosystem), escapeMD(f.VulnID), escapeMD(f.Summary))
	}
	return []byte(b.String())
}

func safe(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func escapeMD(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func parseFailOn(s string) (severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return severityNone, nil
	case "low":
		return severityLow, nil
	case "medium":
		return severityMedium, nil
	case "high":
		return severityHigh, nil
	case "critical":
		return severityCritical, nil
	default:
		return severityNone, fmt.Errorf("invalid --fail-on value: %q (use none|low|medium|high|critical)", s)
	}
}

func shouldFail(maxSeen, threshold severity) bool {
	if threshold == severityNone {
		return false
	}
	return sevRank(maxSeen) >= sevRank(threshold)
}

func mapCVSS(sevs []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) severity {
	max := 0.0
	for _, s := range sevs {
		var v float64
		fmt.Sscanf(s.Score, "%f", &v)
		if v > max {
			max = v
		}
	}
	switch {
	case max >= 9.0:
		return severityCritical
	case max >= 7.0:
		return severityHigh
	case max >= 4.0:
		return severityMedium
	case max > 0:
		return severityLow
	default:
		return severityLow
	}
}

/********** runtime summary helpers **********/

type runtimeSummary struct {
	Total    int
	Active   int
	Observed int
	Dormant  int
}

func summarizeRuntime(fr *findingsResponse) runtimeSummary {
	var s runtimeSummary
	for _, f := range fr.Findings {
		s.Total++
		switch f.RuntimeState {
		case "active":
			s.Active++
		case "observed":
			s.Observed++
		case "dormant":
			s.Dormant++
		}
	}
	return s
}

func maybePrintRuntimeSummary(projectSlug string) {
	fr, err := fetchFindings(projectSlug)
	if err != nil {
		// Don't fail the scan if API is down; just warn.
		fmt.Fprintf(os.Stderr, "⚠ runtime summary unavailable for %s: %v\n", projectSlug, err)
		return
	}

	s := summarizeRuntime(fr)

	if s.Total == 0 {
		fmt.Printf("\nRuntime summary for %s: no stored findings yet.\n", projectSlug)
		return
	}

	fmt.Printf(
		"\nRuntime summary for %s: %d findings (%d active, %d observed, %d dormant).\n",
		projectSlug, s.Total, s.Active, s.Observed, s.Dormant,
	)
}
