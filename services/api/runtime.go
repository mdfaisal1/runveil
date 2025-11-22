// services/api/runtime.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// A single package that the agent observed at runtime.
type RuntimePackage struct {
	Name    string `json:"name" binding:"required"`
	Version string `json:"version" binding:"required"`
}

// Request body for /runtime/observe.
type RuntimeObservationRequest struct {
	Packages    []RuntimePackage `json:"packages" binding:"required"`
	Environment string           `json:"environment"`           // e.g. "dev-local", "prod"
	ObservedAt  *time.Time       `json:"observed_at,omitempty"` // optional; defaults to now()
}

// Register the runtime observation route with Gin.
func registerRuntime(r *gin.Engine, db *sql.DB) {
	r.POST("/v1/projects/:slug/runtime/observe", func(c *gin.Context) {
		slug := c.Param("slug")

		var req RuntimeObservationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid payload",
				"details": err.Error(),
			})
			return
		}
		if len(req.Packages) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "packages must not be empty"})
			return
		}

		observedAt := time.Now().UTC()
		if req.ObservedAt != nil {
			observedAt = req.ObservedAt.UTC()
		}

		ctx := c.Request.Context()
		updated, err := applyRuntimeObservation(ctx, db, slug, &req, observedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"packages":         len(req.Packages),
			"findings_updated": updated,
		})
	})
}

// applyRuntimeObservation updates findings for the observed packages.
func applyRuntimeObservation(
	ctx context.Context,
	db *sql.DB,
	slug string,
	req *RuntimeObservationRequest,
	observedAt time.Time,
) (int64, error) {
	if slug == "" {
		return 0, errors.New("missing project slug")
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op if already committed

	var totalUpdated int64

	for _, p := range req.Packages {
		// 1) Find all package IDs for this project + name + version.
		rows, err := tx.QueryContext(ctx, `
			SELECT p.id
			FROM packages p
			JOIN scans s   ON p.scan_id = s.id
			JOIN projects pr ON s.project_id = pr.id
			WHERE pr.slug = $1
			  AND p.name = $2
			  AND p.version = $3
		`, slug, p.Name, p.Version)
		if err != nil {
			return 0, err
		}

		var pkgIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, err
			}
			pkgIDs = append(pkgIDs, id)
		}
		rows.Close()

		// 2) For each package, mark all its findings as reachable and update evidence.
		for _, pkgID := range pkgIDs {
			res, err := tx.ExecContext(ctx, `
				UPDATE findings
				SET reachable      = true,
				    evidence_count = evidence_count + 1,
				    first_seen_at  = COALESCE(first_seen_at, $2),
				    last_seen_at   = $2,
				    updated_at     = now()
				WHERE package_id = $1
			`, pkgID, observedAt)
			if err != nil {
				return 0, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, err
			}
			totalUpdated += n
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return totalUpdated, nil
}
