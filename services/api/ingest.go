// services/api/ingest.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	Component    string      `json:"component"`     // optional: key of a manifest-declared component
	Packages     []IngestPkg `json:"packages"`      // list of packages with embedded vulns
}

// errComponentNotFound is returned by ingest when a scan references a component
// key that hasn't been registered. Components are manifest-declared, so the
// handler surfaces this as 404 rather than silently creating one.
var errComponentNotFound = errors.New("component not found")

// errWrongOrg is returned when an API key tries to ingest into a project that
// belongs to a different organization (cross-tenant write).
var errWrongOrg = errors.New("project belongs to a different organization")

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
	ProjectCreated  bool   `json:"project_created,omitempty"`
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
	// CLI-only, data-integrity-critical route: require an API key so a fake
	// scan can't be ingested by anyone who can reach the port.
	r.POST("/v1/projects/:slug/scans/ingest", requireAPIKey(db), func(c *gin.Context) {
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
		orgID := c.GetString(ctxOrgID) // set by requireAPIKey from the key's org
		if orgID == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "API key is not scoped to an organization"})
			return
		}
		resp, err := ingest(ctx, db, slug, orgID, &req, env.Report)
		if err != nil {
			if errors.Is(err, errComponentNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, errWrongOrg) {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if resp.ProjectCreated {
			auditCtx(c, db, "project.created", slug, map[string]any{"via": "ingest"})
		}
		c.JSON(http.StatusOK, resp)
	})
}

// ---------- core ingest transaction ----------

func ingest(ctx context.Context, db *sql.DB, slug, orgID string, req *IngestRequest, rawReport json.RawMessage) (*IngestResponse, error) {
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

	// 1) upsert project, scoped to the API key's org. A new project is created
	// under that org; an existing project must already belong to it, else this
	// is a cross-tenant write and we reject.
	var (
		projectID  string
		projectOrg string
		created    bool
	)
	// (xmax = 0) is true only when this row was freshly INSERTed in this txn,
	// letting us tell a new project from an existing one for the audit log.
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO projects (slug, name, org_id)
		VALUES ($1, $1, $2)
		ON CONFLICT (slug) DO UPDATE SET updated_at = now()
		RETURNING id, org_id, (xmax = 0) AS created
	`, slug, orgID).Scan(&projectID, &projectOrg, &created); err != nil {
		return nil, err
	}
	if projectOrg != orgID {
		return nil, errWrongOrg
	}

	// 1b) resolve optional component (manifest-declared: must already exist)
	var componentID sql.NullString
	if key := strings.TrimSpace(strings.ToLower(req.Component)); key != "" {
		var id string
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM components WHERE project_id = $1 AND key = $2`,
			projectID, key).Scan(&id)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: %q (register it first via POST /v1/projects/%s/components)", errComponentNotFound, key, slug)
		}
		if err != nil {
			return nil, err
		}
		componentID = sql.NullString{String: id, Valid: true}
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
		INSERT INTO scans (project_id, status, source, lockfile_path, report_json, component_id, started_at, finished_at)
		VALUES ($1, 'succeeded', $2, $3, $4::jsonb, $5, now(), now())
		RETURNING id
	`, projectID, req.Source, req.LockfilePath, reportJSON, componentID).Scan(&scanID); err != nil {
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
		ProjectCreated:  created,
	}, nil
}

// handy if you ever need a context with timeout inside helpers
func withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
