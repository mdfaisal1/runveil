// services/api/ingest.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------- request/response DTOs ----------

type IngestRequest struct {
	Source       string      `json:"source"`        // e.g. "cli"
	LockfilePath string      `json:"lockfile_path"` // optional
	Packages     []IngestPkg `json:"packages"`      // list of packages with embedded vulns
}

type IngestPkg struct {
	Ecosystem string          `json:"ecosystem"` // npm, pypi, cargo...
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Vulns     []IngestFinding `json:"vulns"` // per-package vulns
}

type IngestFinding struct {
	Source        string `json:"source"`  // "osv" or "nvd"
	VulnID        string `json:"vuln_id"` // e.g. "GHSA-xxxx", "CVE-2024-xxxx"
	Summary       string `json:"summary,omitempty"`
	Severity      string `json:"severity,omitempty"` // LOW|MEDIUM|HIGH|CRITICAL (normalized)
	FixedVersion  string `json:"fixed_version,omitempty"`
	Reachable     bool   `json:"reachable"` // static reachability from the scan (production dep)
	Dev           bool   `json:"dev"`       // dev-only dependency (dormant)
	Direct        bool   `json:"direct"`    // listed directly in the project's dependencies
	IntroducedVia string `json:"introduced_via,omitempty"`
}

type rawScanReport struct {
	ProjectSlug string           `json:"project_slug"`
	Total       int              `json:"total"`
	Findings    []rawScanFinding `json:"findings"`
	MaxSeverity string           `json:"max_severity"`
	GeneratedAt string           `json:"generated_at"`
}

type rawScanFinding struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	VulnID    string `json:"vuln_id"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Reachable bool   `json:"reachable"`
	Dev       bool   `json:"dev"`
	Direct    bool   `json:"direct"`
}

type IngestResponse struct {
	ScanID          string `json:"scan_id"`
	Packages        int    `json:"packages"`
	Vulnerabilities int    `json:"vulnerabilities"`
	Findings        int    `json:"findings"`
}

// Used to detect an alternate payload shape: { "report": <json> }
type rawReportEnvelope struct {
	Report json.RawMessage `json:"report"`
}

// ---------- router hookup ----------

func derivePackagesFromReport(raw json.RawMessage) []IngestPkg {
	if len(raw) == 0 {
		return nil
	}

	var rep rawScanReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		// best-effort: if we can't parse, just return nil and let caller ignore
		return nil
	}
	if len(rep.Findings) == 0 {
		return nil
	}

	type key struct {
		Ecosystem string
		Name      string
		Version   string
	}

	m := make(map[key]*IngestPkg)

	for _, f := range rep.Findings {
		k := key{
			Ecosystem: f.Ecosystem,
			Name:      f.Package,
			Version:   f.Version,
		}
		if k.Ecosystem == "" {
			k.Ecosystem = "npm"
		}

		pkg := m[k]
		if pkg == nil {
			pkg = &IngestPkg{
				Ecosystem: k.Ecosystem,
				Name:      k.Name,
				Version:   k.Version,
			}
			m[k] = pkg
		}

		sev := strings.ToUpper(f.Severity)

		pkg.Vulns = append(pkg.Vulns, IngestFinding{
			Source:    "osv", // we currently scan via OSV
			VulnID:    f.VulnID,
			Summary:   f.Summary,
			Severity:  sev,
			Reachable: f.Reachable, // static reachability computed by the scanner
			Dev:       f.Dev,
			Direct:    f.Direct,
			// FixedVersion, IntroducedVia left as zero values
		})
	}

	out := make([]IngestPkg, 0, len(m))
	for _, pkg := range m {
		out = append(out, *pkg)
	}
	return out
}

func registerIngest(r *gin.Engine, db *sql.DB) {
	r.POST("/v1/projects/:slug/scans/ingest", func(c *gin.Context) {
		slug := c.Param("slug")

		// Read the raw body once so we can:
		// 1) Bind into IngestRequest (structured path)
		// 2) Optionally extract { "report": ... } (raw report path)
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
			return
		}

		// Parse structured shape (best-effort; we don't fail if empty)
		var req IngestRequest
		_ = json.Unmarshal(body, &req)

		// Detect optional raw report field
		var env rawReportEnvelope
		_ = json.Unmarshal(body, &env)

		ctx := c.Request.Context()
		resp, err := ingest(ctx, db, slug, &req, env.Report)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp)
	})
}

// ---------- core ingest transaction ----------

func ingest(ctx context.Context, db *sql.DB, slug string, req *IngestRequest, rawReport json.RawMessage) (*IngestResponse, error) {
	if slug == "" {
		return nil, errors.New("missing project slug")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback() // no-op if already committed
	}()

	if len(req.Packages) == 0 && len(rawReport) != 0 {
		if pkgs := derivePackagesFromReport(rawReport); len(pkgs) > 0 {
			req.Packages = pkgs
		}
	}

	// 1) upsert project
	var projectID string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO projects (slug, name)
		VALUES ($1, $1)
		ON CONFLICT (slug) DO UPDATE SET updated_at = now()
		RETURNING id
	`, slug).Scan(&projectID); err != nil {
		return nil, err
	}

	// 2) Decide what to store in scans.report_json
	// Prefer the raw "report" if present (e.g., from the CLI step we added).
	// Otherwise, synthesize a minimal envelope from the structured request.
	reportJSON := rawReport
	if len(reportJSON) == 0 {
		type synth struct {
			ProjectSlug string      `json:"project_slug"`
			Source      string      `json:"source,omitempty"`
			Lockfile    string      `json:"lockfile_path,omitempty"`
			Packages    []IngestPkg `json:"packages"`
			GeneratedAt string      `json:"generated_at"`
			Totals      struct {
				Packages int `json:"packages"`
				Findings int `json:"findings"`
			} `json:"totals"`
		}
		s := synth{
			ProjectSlug: slug,
			Source:      req.Source,
			Lockfile:    req.LockfilePath,
			Packages:    req.Packages,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}
		pkgs, fnds := 0, 0
		for _, p := range req.Packages {
			pkgs++
			fnds += len(p.Vulns)
		}
		s.Totals.Packages = pkgs
		s.Totals.Findings = fnds

		b, _ := json.Marshal(s)
		reportJSON = b
	}

	// 3) create scan row (store the JSON in report_json; keep your existing fields)
	var scanID string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO scans (project_id, status, source, lockfile_path, report_json, started_at, finished_at)
		VALUES ($1, 'succeeded', $2, $3, $4::jsonb, now(), now())
		RETURNING id
	`, projectID, req.Source, req.LockfilePath, reportJSON).Scan(&scanID); err != nil {
		return nil, err
	}

	// Snapshot which (package, version, vuln) were ALREADY reachable for this
	// project, so we can detect findings that become reachable in this scan and
	// alert on them. Runs before this scan's rows are inserted.
	priorReachable := map[string]bool{}
	if prRows, err := tx.QueryContext(ctx, `
		SELECT p.name, p.version, v.vuln_id
		FROM findings f
		JOIN packages p        ON p.id = f.package_id
		JOIN scans s           ON s.id = p.scan_id
		JOIN projects proj     ON proj.id = s.project_id
		JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE proj.slug = $1 AND f.reachable = true
	`, slug); err == nil {
		for prRows.Next() {
			var n, ver, vid string
			if err := prRows.Scan(&n, &ver, &vid); err == nil {
				priorReachable[n+"@"+ver+"|"+vid] = true
			}
		}
		prRows.Close()
	}
	var newReachable []slackFinding

	// 4) insert packages + (upsert) vulnerabilities + findings (same as before)
	pkgs := 0
	vulnUpserts := 0
	findings := 0

	for _, p := range req.Packages {
		var pkgID string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO packages (scan_id, ecosystem, name, version)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (scan_id, ecosystem, name, version)
			DO UPDATE SET updated_at = now()
			RETURNING id
		`, scanID, p.Ecosystem, p.Name, p.Version).Scan(&pkgID); err != nil {
			return nil, err
		}
		pkgs++

		for _, v := range p.Vulns {
			var vulnID string
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO vulnerabilities (source, vuln_id, summary, severity, created_at, updated_at)
				VALUES ($1, $2, $3, $4, now(), now())
				ON CONFLICT (source, vuln_id)
				DO UPDATE SET summary = EXCLUDED.summary,
				              severity = EXCLUDED.severity,
				              updated_at = now()
				RETURNING id
			`, v.Source, v.VulnID, v.Summary, v.Severity).Scan(&vulnID); err != nil {
				return nil, err
			}
			vulnUpserts++

			if _, err := tx.ExecContext(ctx, `
				INSERT INTO findings (package_id, vulnerability_id, reachable, is_dev, is_direct, fixed_version, introduced_via)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (package_id, vulnerability_id)
				DO UPDATE SET reachable = findings.reachable OR EXCLUDED.reachable,
				              is_dev = EXCLUDED.is_dev,
				              is_direct = EXCLUDED.is_direct,
				              fixed_version = EXCLUDED.fixed_version,
				              introduced_via = EXCLUDED.introduced_via,
				              updated_at = now()
			`, pkgID, vulnID, v.Reachable, v.Dev, v.Direct, v.FixedVersion, v.IntroducedVia); err != nil {
				return nil, err
			}
			findings++

			// Collect newly-reachable HIGH/CRITICAL findings to alert on.
			sev := strings.ToUpper(v.Severity)
			if v.Reachable && (sev == "HIGH" || sev == "CRITICAL") {
				key := p.Name + "@" + p.Version + "|" + v.VulnID
				if !priorReachable[key] {
					newReachable = append(newReachable, slackFinding{
						Severity: sev, Package: p.Name, Version: p.Version, VulnID: v.VulnID,
					})
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Alert on newly-reachable high/critical findings (best-effort, non-blocking).
	if len(newReachable) > 0 {
		if webhook := projectSlackWebhook(ctx, db, slug); webhook != "" {
			go notifySlackNewReachable(webhook, slug, newReachable)
		}
	}

	return &IngestResponse{
		ScanID:          scanID,
		Packages:        pkgs,
		Vulnerabilities: vulnUpserts,
		Findings:        findings,
	}, nil
}

// handy if you ever need a context with timeout inside helpers
func withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
