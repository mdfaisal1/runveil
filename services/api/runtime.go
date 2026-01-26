// services/api/runtime.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
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
		ctx := c.Request.Context()
		slug := c.Param("slug")

		// 1) Auth: require a valid runtime token
		token := c.GetHeader("X-Runveil-Token")
		if strings.TrimSpace(token) == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "missing runtime token (X-Runveil-Token)",
			})
			return
		}

		var ok bool
		err := db.QueryRowContext(ctx, `
			SELECT true
			FROM projects
			WHERE slug = $1
			  AND runtime_token = $2
		`, slug, token).Scan(&ok)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid runtime token for project",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "failed to verify runtime token",
				"details": err.Error(),
			})
			return
		}

		// 2) Parse payload
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

// deriveRuntimeState computes a simple runtime state for a finding
// from its evidence fields. This is DYNAMIC: not stored in DB, only
// computed when we read.
func deriveRuntimeState(evidenceCount int64, lastSeenAt *time.Time) string {
	// Never seen at runtime → dormant
	if evidenceCount == 0 || lastSeenAt == nil {
		return "dormant"
	}

	// If we have evidence, decide how "fresh" it is.
	const activeWindow = 24 * time.Hour
	now := time.Now().UTC()

	if now.Sub(*lastSeenAt) <= activeWindow {
		// Recently seen (last 24h) → active
		return "active"
	}

	// Seen in the past, but not recently → observed
	return "observed"
}
