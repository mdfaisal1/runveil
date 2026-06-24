// services/api/audit.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ctxAPIKeyPrefix carries the calling key's display prefix (for audit labels).
const ctxAPIKeyPrefix = "api_key_prefix"

// recordAudit appends one append-only audit row. Best-effort: a failure is
// logged but never propagates, so it can't roll back or fail the real action.
// Always called AFTER the audited action has committed.
func recordAudit(ctx context.Context, db *sql.DB, orgID, actorUserID, actorLabel, action, target string, metadata map[string]any, ip string) {
	if orgID == "" {
		// Every audit row must belong to an org (NOT NULL). An unattributable
		// event is dropped here and only the app log records it.
		log.Printf("audit skipped (no org): action=%s target=%s actor=%s", action, target, actorLabel)
		return
	}
	var metaJSON any
	if len(metadata) > 0 {
		if b, err := json.Marshal(metadata); err == nil {
			metaJSON = b
		}
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_log (org_id, actor_user_id, actor_label, action, target, metadata, ip)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
	`, orgID, nullableStr(actorUserID), actorLabel, action, nullableStr(target), metaJSON, nullableStr(ip)); err != nil {
		log.Printf("audit write failed: action=%s target=%s err=%v", action, target, err)
	}
}

// auditCtx records an audit event for a request that has passed through an auth
// middleware (org + actor are on the context). Derives the actor across the
// session / API-key / system credential types.
func auditCtx(c *gin.Context, db *sql.DB, action, target string, metadata map[string]any) {
	orgID := c.GetString(ctxOrgID)
	actorUserID, actorLabel := ctxActor(c, db)
	recordAudit(c.Request.Context(), db, orgID, actorUserID, actorLabel, action, target, metadata, c.ClientIP())
}

// ctxActor resolves the human-readable actor for the current request.
func ctxActor(c *gin.Context, db *sql.DB) (userID, label string) {
	if uid := c.GetString(ctxUserID); uid != "" {
		var email string
		_ = db.QueryRowContext(c.Request.Context(), `SELECT email FROM users WHERE id = $1`, uid).Scan(&email)
		if email == "" {
			email = uid
		}
		return uid, email
	}
	if pfx := c.GetString(ctxAPIKeyPrefix); pfx != "" {
		return "", "api-key:" + pfx
	}
	if c.GetString(ctxAPIKeyID) != "" {
		return "", "api-key"
	}
	return "", "system"
}

type auditView struct {
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    *string        `json:"target,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	IP        *string        `json:"ip,omitempty"`
	CreatedAt time.Time      `json:"at"`
}

// registerAudit exposes the org's audit trail to admins+.
//
//	GET /v1/org/audit?limit=N&action=prefix   (limit default 100, max 500)
func registerAudit(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/org/audit", requireAuth(db), requireRole("admin"), func(c *gin.Context) {
		ctx := c.Request.Context()
		orgID := c.GetString(ctxOrgID)
		limit := clampInt(c.Query("limit"), 100, 1, 500)
		actionFilter := c.Query("action")

		rows, err := db.QueryContext(ctx, `
			SELECT actor_label, action, target, metadata, ip, created_at
			FROM audit_log
			WHERE org_id = $1
			  AND ($2 = '' OR action LIKE $2 || '%')
			ORDER BY created_at DESC
			LIMIT $3
		`, orgID, actionFilter, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query audit log"})
			return
		}
		defer rows.Close()

		out := []auditView{}
		for rows.Next() {
			var (
				av     auditView
				target sql.NullString
				ip     sql.NullString
				meta   []byte
			)
			if err := rows.Scan(&av.Actor, &av.Action, &target, &meta, &ip, &av.CreatedAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan audit log"})
				return
			}
			if target.Valid {
				av.Target = &target.String
			}
			if ip.Valid {
				av.IP = &ip.String
			}
			if len(meta) > 0 {
				_ = json.Unmarshal(meta, &av.Metadata)
			}
			out = append(out, av)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating audit log"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"entries": out})
	})
}
