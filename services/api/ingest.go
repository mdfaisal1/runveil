// services/api/ingest.go
package main

import (
	"context"
	"database/sql"
	"errors"
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

// ---------- router hookup ----------

func registerIngest(r *gin.Engine, db *sql.DB) {
	r.POST("/v1/projects/:slug/scans/ingest", func(c *gin.Context) {
		slug := c.Param("slug")
		var req IngestRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx := c.Request.Context()
		resp, err := ingest(ctx, db, slug, &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp)
	})
}

// ---------- core ingest transaction ----------

func ingest(ctx context.Context, db *sql.DB, slug string, req *IngestRequest) (*IngestResponse, error) {
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

	// 2) create scan row (mark succeeded for now; later you can stream updates)
	var scanID string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO scans (project_id, status, source, lockfile_path, started_at, finished_at)
		VALUES ($1, 'succeeded', $2, $3, now(), now())
		RETURNING id
	`, projectID, req.Source, req.LockfilePath).Scan(&scanID); err != nil {
		return nil, err
	}

	pkgs := 0
	vulnUpserts := 0
	findings := 0

	// 3) insert packages + (upsert) vulnerabilities + findings
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
