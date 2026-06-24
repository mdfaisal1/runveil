// services/api/auth.go
package main

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mdfaisal1/runveil/pkg/infra"
)

// Context keys for values the auth middleware attaches to the request.
const (
	ctxAPIKeyID    = "api_key_id"
	ctxAPIKeyScope = "api_key_scope"
)

// requireAPIKey returns Gin middleware that authenticates the caller via an
// "Authorization: Bearer rv_..." header against the api_keys table.
//
// v1 scope: this guards non-browser, data-mutating routes (currently only
// scans/ingest). Browser-driven routes (reads, settings) stay open until the
// dashboard ships a credential — see ONBOARDING / the auth notes.
//
// The key is hashed before lookup; the plaintext is never stored or logged.
// A successful match updates last_used_at and stashes the key id + scope on
// the context for handlers that want to scope by it later.
func requireAPIKey(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing API key (Authorization: Bearer rv_...)",
			})
			return
		}

		hash := infra.HashAPIKey(token)

		var (
			id    string
			scope string
			orgID sql.NullString
		)
		err := db.QueryRowContext(c.Request.Context(), `
			SELECT id, scope, org_id
			FROM api_keys
			WHERE key_hash = $1
			  AND revoked_at IS NULL
		`, hash).Scan(&id, &scope, &orgID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid or revoked API key",
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "failed to verify API key",
			})
			return
		}

		// Best-effort touch; never fail the request on this.
		_, _ = db.ExecContext(c.Request.Context(),
			`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)

		c.Set(ctxAPIKeyID, id)
		c.Set(ctxAPIKeyScope, scope)
		if orgID.Valid {
			c.Set(ctxOrgID, orgID.String)
		}
		c.Next()
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. Returns "" if absent or malformed.
func bearerToken(c *gin.Context) string {
	h := strings.TrimSpace(c.GetHeader("Authorization"))
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
