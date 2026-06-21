package main

import (
	"database/sql"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
)

// registerHotspots returns a project's findings ranked by risk score (highest first).
//
//	GET /v1/projects/:slug/hotspots?limit=N   (default 20, max 200)
func registerHotspots(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/projects/:slug/hotspots", func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")
		limit := clampInt(c.Query("limit"), 20, 1, 200)

		rows, err := db.QueryContext(ctx, `
SELECT f.id, p.name, p.version, p.ecosystem,
       v.vuln_id, v.summary, v.severity,
       f.reachable, f.is_dev, f.is_direct,
       f.evidence_count, f.last_seen_at
FROM findings f
JOIN packages p        ON p.id = f.package_id
JOIN scans s           ON s.id = p.scan_id
JOIN projects proj     ON proj.id = s.project_id
JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE proj.slug = $1
  AND s.id = (SELECT id FROM scans WHERE project_id = proj.id ORDER BY created_at DESC LIMIT 1)
`, slug)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query hotspots", "details": err.Error()})
			return
		}
		defer rows.Close()

		var out []FindingView
		for rows.Next() {
			var v FindingView
			if err := rows.Scan(
				&v.ID, &v.Package, &v.Version, &v.Ecosystem,
				&v.VulnID, &v.Summary, &v.Severity,
				&v.Reachable, &v.IsDev, &v.IsDirect,
				&v.EvidenceCount, &v.LastSeenAt,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan hotspots"})
				return
			}
			v.RuntimeState = deriveRuntimeState(v.EvidenceCount, v.LastSeenAt)
			v.RiskScore = riskScore(v.Reachable, v.Severity, v.EvidenceCount)
			out = append(out, v)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating hotspots"})
			return
		}

		// Rank by risk desc, then evidence, then severity rank as tiebreakers.
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].RiskScore != out[j].RiskScore {
				return out[i].RiskScore > out[j].RiskScore
			}
			if out[i].EvidenceCount != out[j].EvidenceCount {
				return out[i].EvidenceCount > out[j].EvidenceCount
			}
			return out[i].Package < out[j].Package
		})
		if len(out) > limit {
			out = out[:limit]
		}

		c.JSON(http.StatusOK, gin.H{"project_slug": slug, "hotspots": out})
	})
}
