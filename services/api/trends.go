// services/api/trends.go
package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TrendPoint is one scan's worth of aggregated counts, used to plot how a
// project's vulnerability posture moves over time.
//
// We deliberately track COUNTS, not risk. risk_score/evidence_count are live
// denormalized counters updated out-of-band by the runtime agent, so charting
// them against historical scans would plot today's evidence on yesterday's bar.
// Counts that live on the per-scan finding row (total, reachable) are honest;
// severity is latest-wins on the canonical vuln row but accurate in practice.
type TrendPoint struct {
	ScanID      string    `json:"scan_id"`
	At          time.Time `json:"at"`
	ComponentID string    `json:"component_id,omitempty"`
	Total       int       `json:"total"`
	Reachable   int       `json:"reachable"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
}

// TrendSummary captures the current posture and the delta vs. the previous scan
// so the UI can show "↑3 since last scan" without recomputing client-side.
type TrendSummary struct {
	Scans           int `json:"scans"`
	LatestTotal     int `json:"latest_total"`
	PreviousTotal   int `json:"previous_total"`
	DeltaTotal      int `json:"delta_total"`
	LatestReachable int `json:"latest_reachable"`
	DeltaReachable  int `json:"delta_reachable"`
}

type TrendsResponse struct {
	ProjectSlug string       `json:"project_slug"`
	Points      []TrendPoint `json:"points"`
	Summary     TrendSummary `json:"summary"`
}

// registerTrends exposes a project's per-scan metric time series (oldest→newest).
//
//	GET /v1/projects/:slug/trends?limit=N&component=<key>   (limit default 60, max 365)
//
// Without ?component, all scans across all components share one axis — useful at
// the project level but the deltas only make sense when adjacent scans belong to
// the same component, which summarizeTrend enforces. With ?component the timeline
// is scoped to that one component, matching the findings/hotspots filter.
func registerTrends(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/projects/:slug/trends", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")
		limit := clampInt(c.Query("limit"), 60, 1, 365)
		componentParam := strings.ToLower(strings.TrimSpace(c.Query("component")))

		// The aggregation is identical; only the set of "recent" scans differs by
		// whether we scope to a single component. Return oldest→newest so the
		// client can plot left-to-right without reversing.
		const aggTail = `
SELECT r.id,
       r.started_at,
       r.component_id,
       COUNT(f.id)                                                   AS total,
       COUNT(f.id) FILTER (WHERE f.reachable)                        AS reachable,
       COUNT(f.id) FILTER (WHERE upper(v.severity) = 'CRITICAL')     AS critical,
       COUNT(f.id) FILTER (WHERE upper(v.severity) = 'HIGH')         AS high,
       COUNT(f.id) FILTER (WHERE upper(v.severity) = 'MEDIUM')       AS medium,
       COUNT(f.id) FILTER (WHERE upper(v.severity) = 'LOW')          AS low
FROM recent r
LEFT JOIN packages p        ON p.scan_id = r.id
LEFT JOIN findings f        ON f.package_id = p.id
LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
GROUP BY r.id, r.started_at, r.component_id
ORDER BY r.started_at ASC`

		var query string
		var args []any
		if componentParam != "" {
			query = `
WITH recent AS (
  SELECT s.id, s.started_at, s.component_id
  FROM scans s
  JOIN projects pr   ON pr.id = s.project_id
  JOIN components co ON co.id = s.component_id
  WHERE pr.slug = $1 AND co.key = $2
  ORDER BY s.started_at DESC
  LIMIT $3
)` + aggTail
			args = []any{slug, componentParam, limit}
		} else {
			query = `
WITH recent AS (
  SELECT s.id, s.started_at, s.component_id
  FROM scans s
  JOIN projects pr ON pr.id = s.project_id
  WHERE pr.slug = $1
  ORDER BY s.started_at DESC
  LIMIT $2
)` + aggTail
			args = []any{slug, limit}
		}

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			log.Printf("trends query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query trends"})
			return
		}
		defer rows.Close()

		points := []TrendPoint{}
		for rows.Next() {
			var (
				p      TrendPoint
				compID sql.NullString
			)
			if err := rows.Scan(
				&p.ScanID, &p.At, &compID,
				&p.Total, &p.Reachable,
				&p.Critical, &p.High, &p.Medium, &p.Low,
			); err != nil {
				log.Printf("trends scan failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan trends"})
				return
			}
			if compID.Valid {
				p.ComponentID = compID.String
			}
			points = append(points, p)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating trends"})
			return
		}

		c.JSON(http.StatusOK, TrendsResponse{
			ProjectSlug: slug,
			Points:      points,
			Summary:     summarizeTrend(points),
		})
	})
}

// summarizeTrend derives the latest posture and the delta vs. the previous scan.
func summarizeTrend(points []TrendPoint) TrendSummary {
	s := TrendSummary{Scans: len(points)}
	n := len(points)
	if n == 0 {
		return s
	}
	last := points[n-1]
	s.LatestTotal = last.Total
	s.LatestReachable = last.Reachable
	// Only compute a delta when the two most recent scans are the same component
	// (or both project-level). Comparing api's findings to web's would be noise.
	if n >= 2 && points[n-2].ComponentID == last.ComponentID {
		prev := points[n-2]
		s.PreviousTotal = prev.Total
		s.DeltaTotal = last.Total - prev.Total
		s.DeltaReachable = last.Reachable - prev.Reachable
	}
	return s
}
