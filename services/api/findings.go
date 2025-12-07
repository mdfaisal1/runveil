package main

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// FindingView is what we return to the CLI / UI.
type FindingView struct {
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

type FindingsResponse struct {
	ProjectSlug string        `json:"project_slug"`
	Findings    []FindingView `json:"findings"`
}

// registerFindings registers the GET endpoint that lists findings for a project.
func registerFindings(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/projects/:slug/findings", func(c *gin.Context) {
		slug := c.Param("slug")
		ctx := c.Request.Context()

		rows, err := db.QueryContext(ctx, `
            SELECT
                p.name,
                p.version,
                p.ecosystem,
                v.vuln_id,
                v.summary,
                v.severity,
                f.reachable,
                f.evidence_count,
                f.last_seen_at
                FROM findings f
				JOIN packages p   ON f.package_id = p.id
				JOIN vulnerabilities v ON f.vulnerability_id = v.id
				JOIN scans s      ON p.scan_id = s.id
				JOIN projects pr  ON s.project_id = pr.id
            WHERE pr.slug = $1
            ORDER BY f.updated_at DESC
        `, slug)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var out []FindingView

		for rows.Next() {
			var (
				pkgName   string
				version   string
				ecosystem string
				vulnID    string
				summary   string
				severity  string
				reachable bool
				evidence  int64
				lastSeen  *time.Time
			)

			if err := rows.Scan(
				&pkgName,
				&version,
				&ecosystem,
				&vulnID,
				&summary,
				&severity,
				&reachable,
				&evidence,
				&lastSeen,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			state := deriveRuntimeState(evidence, lastSeen)

			out = append(out, FindingView{
				Package:       pkgName,
				Version:       version,
				Ecosystem:     ecosystem,
				VulnID:        vulnID,
				Summary:       summary,
				Severity:      severity,
				Reachable:     reachable,
				EvidenceCount: evidence,
				LastSeenAt:    lastSeen,
				RuntimeState:  state,
			})
		}

		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, FindingsResponse{
			ProjectSlug: slug,
			Findings:    out,
		})
	})
}
