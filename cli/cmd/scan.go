package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mdfaisal1/runveil/pkg/infra"
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
	// Static reachability (computed at scan time, before any runtime evidence):
	// Reachable is true when the vulnerable package is part of the production
	// dependency tree. Dev-only packages (build/test tooling) are not shipped and
	// are reported as dormant.
	Reachable bool `json:"reachable"`
	Dev       bool `json:"dev"`    // dev-only dependency per the lockfile
	Direct    bool `json:"direct"` // listed directly in the project's dependencies
}

type report struct {
	ProjectSlug     string    `json:"project_slug"`
	Total           int       `json:"total"`
	Reachable       int       `json:"reachable"` // count of statically-reachable findings
	Dormant         int       `json:"dormant"`   // count of dev-only / unreachable findings
	Findings        []finding `json:"findings"`
	MaxSeverity     severity  `json:"max_severity"`           // across all findings
	ReachableMax    severity  `json:"reachable_max_severity"` // across reachable findings only
	NoiseReducedPct int       `json:"noise_reduced_pct"`      // % of findings filtered out as dormant
	GeneratedAt     string    `json:"generated_at"`
}

/********** flags **********/

var (
	flagPost      bool
	flagProject   string
	flagComponent string // optional manifest-declared component key
	flagFormat    string // json|md
	flagOutPath   string // file path for report
	flagFailOn    string // none|low|medium|high|critical
)

/********** command **********/

var scanCmd = &cobra.Command{
	Use:   "scan [path-to-package-lock.json]",
	Short: "Scan a Node.js project (package-lock.json) for vulnerabilities using OSV",
	Long:  "Parses package-lock.json (v2/v3 style), queries the OSV API per dependency, and prints only vulnerable packages.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Fall back to the config-file project when --project is omitted.
		if flagProject == "" {
			flagProject = infra.ConfigProject()
		}
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
		maxSeen := severityNone      // across all findings
		maxReachable := severityNone // across reachable (production) findings only

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

			reachable := !d.dev // v1 static reachability: production deps are reachable
			marker := "🚨"
			if !reachable {
				marker = "💤" // dev-only → dormant
			}

			vulnCount += len(res.Vulns)
			fmt.Printf("  %s %s@%s — %d vuln(s)%s\n", marker, d.name, d.version, len(res.Vulns), dormantSuffix(reachable))
			for _, v := range res.Vulns {
				s := strings.Split(strings.TrimSpace(v.Summary), "\n")[0]
				if len(s) > 110 {
					s = s[:110] + "…"
				}
				sev := severityOf(v)
				if sevRank(sev) > sevRank(maxSeen) {
					maxSeen = sev
				}
				if reachable && sevRank(sev) > sevRank(maxReachable) {
					maxReachable = sev
				}
				fmt.Printf("     • %s — %s\n", v.ID, s)

				findings = append(findings, finding{
					Package:   d.name,
					Version:   d.version,
					Ecosystem: "npm",
					VulnID:    v.ID,
					Summary:   s,
					Severity:  sev,
					Reachable: reachable,
					Dev:       d.dev,
					Direct:    d.direct,
				})
			}
		}

		if vulnCount == 0 {
			fmt.Println("✅ No known vulnerabilities found for the packages in this lockfile (per OSV).")
		}

		// Sort reachable findings first, then by severity (so the short list that
		// matters is at the top of every report).
		sortFindings(findings)

		reachableCount := 0
		for _, f := range findings {
			if f.Reachable {
				reachableCount++
			}
		}
		dormantCount := len(findings) - reachableCount
		noiseReduced := 0
		if len(findings) > 0 {
			noiseReduced = int(float64(dormantCount) / float64(len(findings)) * 100)
		}

		// Build report
		rep := report{
			ProjectSlug:     flagProject,
			Total:           len(findings),
			Reachable:       reachableCount,
			Dormant:         dormantCount,
			Findings:        findings,
			MaxSeverity:     maxSeen,
			ReachableMax:    maxReachable,
			NoiseReducedPct: noiseReduced,
			GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		}

		// The headline of every report: reachable of total.
		fmt.Printf("\n📊 %d reachable of %d total", reachableCount, len(findings))
		if dormantCount > 0 {
			fmt.Printf("  ·  %d dormant (dev-only) hidden  ·  %d%% noise reduced", dormantCount, noiseReduced)
		}
		fmt.Println()

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
			if err := infra.PostScan(ctx, flagProject, flagComponent, reportJSON); err != nil {
				fmt.Printf("❌ post failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("📤 Posted scan to Runveil API.")
		}

		// 🔥 NEW: runtime summary (if a project slug is provided)
		if flagProject != "" {
			maybePrintRuntimeSummary(flagProject)
		}

		// CI/CD gating — gate on REACHABLE severity, not total noise. This is the
		// point of Runveil: a wall of dormant dev-only CVEs should not fail your build.
		if shouldFail(maxReachable, threshold) {
			fmt.Printf("⛔ Policy fail: max reachable severity %s ≥ --fail-on %s\n", strings.ToUpper(string(maxReachable)), strings.ToUpper(string(threshold)))
			os.Exit(3) // dedicated exit code for policy violation
		}
	},
}

func init() {
	// Existing flags
	scanCmd.Flags().BoolVar(&flagPost, "post", false, "Send the generated report to Runveil API")
	scanCmd.Flags().StringVar(&flagProject, "project", "", "Project slug (required with --post)")
	scanCmd.Flags().StringVar(&flagComponent, "component", "", "Attach this scan to a registered component (key); requires --post")
	scanCmd.Flags().StringVar(&flagFormat, "format", "json", "Report format: json|md")
	scanCmd.Flags().StringVar(&flagOutPath, "out", "", "Write report to this file (otherwise stdout)")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "none", "Fail build if max severity meets/exceeds this level: none|low|medium|high|critical")
}

/********** helpers already used **********/

type dep struct {
	name    string
	version string
	dev     bool // dev-only dependency (npm "dev"/"devOptional" flag)
	direct  bool // listed in the root package's dependencies/devDependencies
}

// directDepNames returns the set of package names listed directly in the root
// package entry's dependencies/devDependencies/optionalDependencies maps.
func directDepNames(packages map[string]any) map[string]bool {
	set := map[string]bool{}
	root, ok := packages[""].(map[string]any)
	if !ok {
		return set
	}
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		if m, ok := root[field].(map[string]any); ok {
			for name := range m {
				set[name] = true
			}
		}
	}
	return set
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

	direct := directDepNames(packages)

	// npm lockfiles list the same package@version at multiple node_modules paths
	// (nested installs), so dedupe by name+version. When a version appears both in
	// the production and dev trees, production wins (dev only if every copy is dev)
	// and direct wins, so reachability is never understated.
	type nv struct{ name, version string }
	seen := make(map[nv]int, len(packages))
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

		// The package name is the path segment after the LAST "node_modules/", so
		// nested installs resolve to the real package, not its parent. e.g.
		// "node_modules/a/node_modules/@scope/b" → "@scope/b".
		name := k
		if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
			name = k[i+len("node_modules/"):]
		}

		// npm marks packages present only in the dev dependency tree with "dev": true.
		// "devOptional": true means present only via dev and/or optional trees — also
		// not part of a plain production install. Either way → dev-only (dormant).
		devOnly, _ := entry["dev"].(bool)
		devOptional, _ := entry["devOptional"].(bool)
		d := dep{
			name:    name,
			version: ver,
			dev:     devOnly || devOptional,
			direct:  direct[name],
		}

		if idx, ok := seen[nv{name, ver}]; ok {
			// merge: production beats dev, direct beats transitive
			out[idx].dev = out[idx].dev && d.dev
			out[idx].direct = out[idx].direct || d.direct
			continue
		}
		seen[nv{name, ver}] = len(out)
		out = append(out, d)
	}
	return out
}

func renderMarkdown(rep report) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Runveil Scan Report — %s\n\n", safe(rep.ProjectSlug, "N/A"))

	// Headline: reachable of total — the noise-reduction story up front.
	fmt.Fprintf(&b, "## %d reachable of %d total findings\n\n", rep.Reachable, rep.Total)
	if rep.Dormant > 0 {
		fmt.Fprintf(&b, "> **%d%% noise reduced** — %d dormant (dev-only) findings hidden from the list below.\n\n",
			rep.NoiseReducedPct, rep.Dormant)
	}
	fmt.Fprintf(&b, "**Max reachable severity:** %s  •  **Max severity (all):** %s  •  **Generated:** %s UTC\n\n",
		strings.ToUpper(string(safeSev(rep.ReachableMax))), strings.ToUpper(string(safeSev(rep.MaxSeverity))), rep.GeneratedAt)

	if rep.Total == 0 {
		b.WriteString("_No vulnerabilities found._\n")
		return []byte(b.String())
	}
	b.WriteString("| Reachability | Severity | Package | Version | Ecosystem | Vuln ID | Summary |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, f := range rep.Findings {
		reach := "💤 Dormant"
		if f.Reachable {
			reach = "🔥 Reachable"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			reach,
			strings.ToUpper(string(f.Severity)),
			escapeMD(f.Package), escapeMD(f.Version), escapeMD(f.Ecosystem), escapeMD(f.VulnID), escapeMD(f.Summary))
	}
	return []byte(b.String())
}

// safeSev renders "none" when no severity was recorded (e.g. zero reachable findings).
func safeSev(s severity) severity {
	if s == "" {
		return severityNone
	}
	return s
}

func dormantSuffix(reachable bool) string {
	if reachable {
		return ""
	}
	return " (dormant)"
}

// sortFindings orders reachable findings first, then by descending severity,
// then by package name — so the short list that matters sits at the top.
func sortFindings(fs []finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Reachable != b.Reachable {
			return a.Reachable // reachable before dormant
		}
		if sevRank(a.Severity) != sevRank(b.Severity) {
			return sevRank(a.Severity) > sevRank(b.Severity)
		}
		return a.Package < b.Package
	})
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

// severityOf resolves a finding's severity, preferring the source's qualitative
// rating (GitHub/GHSA, which dominates the npm ecosystem) and falling back to a
// computed CVSS v3 base score. OSV puts a CVSS *vector* (not a number) in the
// severity score field, so the qualitative rating is both simpler and what users
// see in `npm audit` / GitHub.
func severityOf(v infra.OSVVuln) severity {
	switch strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return severityCritical
	case "HIGH":
		return severityHigh
	case "MODERATE", "MEDIUM":
		return severityMedium
	case "LOW":
		return severityLow
	}
	if score, ok := infra.CVSSBaseScore(v.Severity); ok {
		return sevFromScore(score)
	}
	return severityLow // a real vuln with no severity data — conservative floor
}

// sevFromScore maps a CVSS base score to a qualitative severity (CVSS v3.1 bands).
func sevFromScore(score float64) severity {
	switch {
	case score >= 9.0:
		return severityCritical
	case score >= 7.0:
		return severityHigh
	case score >= 4.0:
		return severityMedium
	case score > 0:
		return severityLow
	default:
		return severityNone
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
