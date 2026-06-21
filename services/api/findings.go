package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// FindingView is what we return to the CLI / UI.
type FindingView struct {
	ID            string     `json:"id"`
	Package       string     `json:"package"`
	Version       string     `json:"version"`
	Ecosystem     string     `json:"ecosystem"`
	VulnID        string     `json:"vuln_id"`
	Summary       string     `json:"summary"`
	Severity      string     `json:"severity"`
	Reachable     bool       `json:"reachable"`
	IsDev         bool       `json:"is_dev"`    // dev-only dependency (why it's dormant)
	IsDirect      bool       `json:"is_direct"` // direct dependency of the project
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
		ctx := c.Request.Context()
		slug := c.Param("slug")

		log.Printf("listing findings for project slug=%s", slug)

		// --- 1) Read optional filters from query params ---
		// /v1/projects/:slug/findings?reachable=true&has_evidence=true
		reachableParam := strings.ToLower(strings.TrimSpace(c.Query("reachable")))
		hasEvidenceParam := strings.ToLower(strings.TrimSpace(c.Query("has_evidence")))

		// --- 2) Build base query ---
		// Schema (from your migrations):
		//   projects(id, slug, ...)
		//   scans(project_id -> projects.id)
		//   packages(scan_id -> scans.id)
		//   findings(package_id -> packages.id, vulnerability_id -> vulnerabilities.id)
		query := `
SELECT
    f.id,
    p.name,
    p.version,
    p.ecosystem,
    v.vuln_id,
    v.summary,
    v.severity,
    f.reachable,
    f.is_dev,
    f.is_direct,
    f.evidence_count,
    f.last_seen_at
FROM findings f
JOIN packages p        ON p.id = f.package_id
JOIN scans s           ON s.id = p.scan_id
JOIN projects proj     ON proj.id = s.project_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE proj.slug = $1
`

		// --- 3) Apply filters when present ---
		// reachable=true  -> f.reachable = TRUE
		// reachable=false -> f.reachable = FALSE
		if reachableParam == "true" {
			query += " AND f.reachable = TRUE"
		} else if reachableParam == "false" {
			query += " AND f.reachable = FALSE"
		}

		// has_evidence=true  -> f.evidence_count > 0
		// has_evidence=false -> f.evidence_count = 0
		if hasEvidenceParam == "true" {
			query += " AND f.evidence_count > 0"
		} else if hasEvidenceParam == "false" {
			query += " AND f.evidence_count = 0"
		}

		// --- 4) ORDER BY ---
		// Reachable first, then by real severity rank (severity is stored as text,
		// so map it), then package name — mirrors the CLI's "short list first".
		query += `
ORDER BY
    f.reachable DESC,
    CASE upper(v.severity)
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH'     THEN 3
        WHEN 'MEDIUM'   THEN 2
        WHEN 'LOW'      THEN 1
        ELSE 0
    END DESC,
    p.name ASC
`

		// --- 5) Execute query ---
		rows, err := db.QueryContext(ctx, query, slug)
		if err != nil {
			// Log full error + query so we can see what broke (during dev)
			log.Printf("query findings failed: %v\nSQL: %s", err, query)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "failed to query findings",
				"details": err.Error(), // TEMP: show in response during dev
			})
			return
		}
		defer rows.Close()

		var out []FindingView
		for rows.Next() {
			var v FindingView
			if err := rows.Scan(
				&v.ID,
				&v.Package,
				&v.Version,
				&v.Ecosystem,
				&v.VulnID,
				&v.Summary,
				&v.Severity,
				&v.Reachable,
				&v.IsDev,
				&v.IsDirect,
				&v.EvidenceCount,
				&v.LastSeenAt,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "failed to scan findings",
				})
				return
			}

			// derive runtime_state from evidence_count + last_seen_at
			v.RuntimeState = deriveRuntimeState(v.EvidenceCount, v.LastSeenAt)
			out = append(out, v)
		}

		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "error iterating findings rows",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"project_slug": slug,
			"findings":     out,
		})
	})
}
