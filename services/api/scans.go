// services/api/scans.go
package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ScanView is one row in a project's scan history.
type ScanView struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Source       *string    `json:"source,omitempty"`
	LockfilePath *string    `json:"lockfile_path,omitempty"`
	PackageCount int        `json:"package_count"`
	FindingCount int        `json:"finding_count"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

type ScansResponse struct {
	ProjectSlug string     `json:"project_slug"`
	Scans       []ScanView `json:"scans"`
}

// registerScans exposes a project's scan history, newest first.
func registerScans(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/projects/:slug/scans", requireProjectOrg(db), func(c *gin.Context) {
		ctx := c.Request.Context()
		slug := c.Param("slug")

		// One row per scan with package/finding counts. LEFT JOINs so a scan
		// that produced no packages/findings still shows up (count 0).
		rows, err := db.QueryContext(ctx, `
			SELECT s.id,
			       s.status,
			       s.source,
			       s.lockfile_path,
			       COUNT(DISTINCT p.id) AS package_count,
			       COUNT(f.id)          AS finding_count,
			       s.started_at,
			       s.finished_at
			FROM scans s
			JOIN projects pr     ON pr.id = s.project_id
			LEFT JOIN packages p ON p.scan_id = s.id
			LEFT JOIN findings f ON f.package_id = p.id
			WHERE pr.slug = $1
			GROUP BY s.id, s.status, s.source, s.lockfile_path, s.started_at, s.finished_at
			ORDER BY s.started_at DESC
		`, slug)
		if err != nil {
			log.Printf("list scans query failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
			return
		}
		defer rows.Close()

		out := []ScanView{}
		for rows.Next() {
			var (
				sv       ScanView
				source   sql.NullString
				lockfile sql.NullString
				finished sql.NullTime
			)
			if err := rows.Scan(
				&sv.ID, &sv.Status, &source, &lockfile,
				&sv.PackageCount, &sv.FindingCount,
				&sv.StartedAt, &finished,
			); err != nil {
				log.Printf("scan scan failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan scans"})
				return
			}
			if source.Valid {
				sv.Source = &source.String
			}
			if lockfile.Valid {
				sv.LockfilePath = &lockfile.String
			}
			if finished.Valid {
				sv.FinishedAt = &finished.Time
			}
			out = append(out, sv)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating scans"})
			return
		}

		c.JSON(http.StatusOK, ScansResponse{ProjectSlug: slug, Scans: out})
	})
}
