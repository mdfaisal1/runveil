// services/api/ingest.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	Reachable     bool   `json:"reachable"` // set later by agent; allow provided for demo
	IntroducedVia string `json:"introduced_via,omitempty"`
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
				INSERT INTO findings (package_id, vulnerability_id, reachable, fixed_version, introduced_via)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (package_id, vulnerability_id)
				DO UPDATE SET reachable = EXCLUDED.reachable,
				              fixed_version = EXCLUDED.fixed_version,
				              introduced_via = EXCLUDED.introduced_via,
				              updated_at = now()
			`, pkgID, vulnID, v.Reachable, v.FixedVersion, v.IntroducedVia); err != nil {
				return nil, err
			}
			findings++
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
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
