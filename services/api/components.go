// services/api/components.go
package main

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var componentKeyRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// currentScanClause returns the SQL that constrains findings/hotspots to a
// project's *current* posture. It assumes the outer query aliases the projects
// row as `proj` and the scans row as `s`.
//
//   - hasComponent == false (default): the latest scan of each component. Legacy
//     project-level scans (component_id IS NULL) count only if the project has no
//     component scans at all — so adopting components cleanly supersedes them
//     instead of double-counting during the transition.
//   - hasComponent == true ($2 = component key): just that component's latest scan.
func currentScanClause(hasComponent bool) string {
	if hasComponent {
		return `
  AND s.id = (
    SELECT sc.id FROM scans sc
    JOIN components co ON co.id = sc.component_id
    WHERE sc.project_id = proj.id AND co.key = $2
    ORDER BY sc.created_at DESC
    LIMIT 1
  )`
	}
	return `
  AND s.id IN (
    SELECT DISTINCT ON (sc.component_id) sc.id
    FROM scans sc
    WHERE sc.project_id = proj.id
      AND (sc.component_id IS NOT NULL
           OR NOT EXISTS (SELECT 1 FROM scans s3
                          WHERE s3.project_id = proj.id AND s3.component_id IS NOT NULL))
    ORDER BY sc.component_id, sc.created_at DESC
  )`
}

// ComponentView is a registered component plus a rollup of its latest scan.
type ComponentView struct {
	Key            string     `json:"key"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	CreatedAt      time.Time  `json:"created_at"`
	FindingCount   int        `json:"finding_count"`
	ReachableCount int        `json:"reachable_count"`
	MaxSeverity    string     `json:"max_severity"` // "" when no findings yet
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
}

type CreateComponentRequest struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// rankToSeverity inverts the severity ranking used across the codebase.
func rankToSeverity(rank int) string {
	switch rank {
	case 4:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return ""
	}
}

// registerComponents registers list/create endpoints for a project's components.
//
// Components are manifest-declared: they must be registered before a scan can
// attach to one (see ingest.go). List rolls up each component's latest scan.
func registerComponents(r *gin.Engine, db *sql.DB) {

	// ----------------------------
	// LIST components (with rollup)
	// ----------------------------
	r.GET("/v1/projects/:slug/components", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		// For each component, pick its most recent scan (DISTINCT ON), then
		// aggregate that scan's findings. Components with no scans show zeros.
		rows, err := db.QueryContext(ctx, `
WITH latest AS (
  SELECT DISTINCT ON (c.id) c.id AS component_id, s.id AS scan_id, s.started_at
  FROM components c
  JOIN projects pr ON pr.id = c.project_id
  LEFT JOIN scans s ON s.component_id = c.id
  WHERE pr.slug = $1
  ORDER BY c.id, s.started_at DESC NULLS LAST
)
SELECT c.key, c.name, c.kind, c.created_at,
       l.started_at,
       COUNT(f.id)                            AS findings,
       COUNT(f.id) FILTER (WHERE f.reachable) AS reachable,
       COALESCE(MAX(CASE upper(v.severity)
           WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
           WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'  THEN 1 ELSE 0 END), 0) AS max_sev_rank
FROM components c
JOIN projects pr            ON pr.id = c.project_id
LEFT JOIN latest l          ON l.component_id = c.id
LEFT JOIN packages p        ON p.scan_id = l.scan_id
LEFT JOIN findings f        ON f.package_id = p.id
LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
WHERE pr.slug = $1
GROUP BY c.key, c.name, c.kind, c.created_at, l.started_at
ORDER BY max_sev_rank DESC, c.key ASC
`, slug)
		if err != nil {
			log.Printf("list components query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list components"})
			return
		}
		defer rows.Close()

		out := []ComponentView{}
		for rows.Next() {
			var (
				cv       ComponentView
				lastScan sql.NullTime
				sevRank  int
			)
			if err := rows.Scan(
				&cv.Key, &cv.Name, &cv.Kind, &cv.CreatedAt,
				&lastScan, &cv.FindingCount, &cv.ReachableCount, &sevRank,
			); err != nil {
				log.Printf("component scan failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan components"})
				return
			}
			if lastScan.Valid {
				cv.LastScannedAt = &lastScan.Time
			}
			cv.MaxSeverity = rankToSeverity(sevRank)
			out = append(out, cv)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating components"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"project_slug": slug, "components": out})
	})

	// ----------------------------
	// CREATE (register) component
	// ----------------------------
	r.POST("/v1/projects/:slug/components", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		var req CreateComponentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
			return
		}

		req.Key = strings.TrimSpace(strings.ToLower(req.Key))
		req.Name = strings.TrimSpace(req.Name)
		req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
		if req.Name == "" {
			req.Name = req.Key
		}
		if req.Kind == "" {
			req.Kind = "service"
		}
		if req.Key == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "key is required"})
			return
		}
		if !componentKeyRe.MatchString(req.Key) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "key must be lowercase letters, numbers, hyphens only"})
			return
		}

		// Resolve the project (must already exist).
		var projectID string
		err := db.QueryRowContext(ctx, `SELECT id FROM projects WHERE slug = $1`, slug).Scan(&projectID)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
			return
		}
		if err != nil {
			log.Printf("resolve project for component failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create component"})
			return
		}

		var cv ComponentView
		err = db.QueryRowContext(ctx, `
			INSERT INTO components (project_id, key, name, kind)
			VALUES ($1, $2, $3, $4)
			RETURNING key, name, kind, created_at
		`, projectID, req.Key, req.Name, req.Kind).Scan(&cv.Key, &cv.Name, &cv.Kind, &cv.CreatedAt)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "sqlstate 23505") {
				c.JSON(http.StatusConflict, gin.H{"error": "component key already exists"})
				return
			}
			log.Printf("create component failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create component"})
			return
		}

		c.JSON(http.StatusCreated, cv)
	})
}
