// services/api/members.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mdfaisal1/runveil/pkg/infra"
)

// roleRank ranks org roles for RBAC comparisons. Higher = more privilege.
var roleRank = map[string]int{"viewer": 1, "member": 2, "admin": 3, "owner": 4}

// requireRole gates a route on the caller's *session* org role. API-key callers
// have no role (keys carry scopes, not roles) and are therefore rejected — so
// this is only applied to human-stakes routes (settings, member management),
// never to CLI key paths like ingest or component-create.
func requireRole(min string) gin.HandlerFunc {
	need := roleRank[min]
	return func(c *gin.Context) {
		if roleRank[c.GetString(ctxOrgRole)] < need {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "requires " + min + " role or higher"})
			return
		}
		c.Next()
	}
}

const inviteTTL = 7 * 24 * time.Hour

type memberView struct {
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type inviteView struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// registerMembers wires org membership management. List is open to any member;
// mutations require admin (with extra owner-only protections in the handlers).
func registerMembers(r *gin.Engine, db *sql.DB) {
	r.GET("/v1/org/members", requireAuth(db), func(c *gin.Context) { listMembers(c, db) })
	r.POST("/v1/org/members", requireAuth(db), requireRole("admin"), func(c *gin.Context) { addMember(c, db) })
	r.PATCH("/v1/org/members/:userId", requireAuth(db), requireRole("admin"), func(c *gin.Context) { changeRole(c, db) })
	r.DELETE("/v1/org/members/:userId", requireAuth(db), requireRole("admin"), func(c *gin.Context) { removeMember(c, db) })
	r.POST("/v1/org/invites/accept", requireAuth(db), func(c *gin.Context) { acceptInvite(c, db) })
}

func listMembers(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)

	rows, err := db.QueryContext(ctx, `
		SELECT u.id, u.email, u.name, m.role, m.created_at
		FROM org_members m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1
		ORDER BY (m.role = 'owner') DESC, (m.role = 'admin') DESC, u.email
	`, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list members"})
		return
	}
	defer rows.Close()
	members := []memberView{}
	for rows.Next() {
		var m memberView
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Role, &m.JoinedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan members"})
			return
		}
		members = append(members, m)
	}

	invites := []inviteView{}
	irows, err := db.QueryContext(ctx, `
		SELECT email, role, created_at, expires_at
		FROM org_invites WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC
	`, orgID)
	if err == nil {
		defer irows.Close()
		for irows.Next() {
			var iv inviteView
			if err := irows.Scan(&iv.Email, &iv.Role, &iv.CreatedAt, &iv.ExpiresAt); err == nil {
				invites = append(invites, iv)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"members": members, "pending_invites": invites})
}

func addMember(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)

	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if !emailRe.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid email is required"})
		return
	}
	// Admins may grant up to admin; only an owner can mint another owner.
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role == "owner" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot invite directly as owner"})
		return
	}
	if _, ok := roleRank[req.Role]; !ok || req.Role == "owner" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be admin, member, or viewer"})
		return
	}

	// If the user already exists, add membership immediately.
	var existingID string
	err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email) = $1`, req.Email).Scan(&existingID)
	if err == nil {
		_, err = db.ExecContext(ctx, `
			INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role
		`, orgID, existingID, req.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add member"})
			return
		}
		auditCtx(c, db, "member.added", req.Email, map[string]any{"role": req.Role})
		c.JSON(http.StatusOK, gin.H{"added": true, "email": req.Email, "role": req.Role})
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add member"})
		return
	}

	// Otherwise create a tokenized invite, redeemed at signup.
	token, hash, err := infra.GenerateSessionToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invite"})
		return
	}
	invitedBy := nullableStr(c.GetString(ctxUserID))
	// Replace any existing pending invite for this email, then insert fresh.
	if _, err = db.ExecContext(ctx,
		`DELETE FROM org_invites WHERE org_id = $1 AND lower(email) = $2 AND accepted_at IS NULL`,
		orgID, req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invite"})
		return
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO org_invites (org_id, email, role, token_hash, invited_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, orgID, req.Email, req.Role, hash, invitedBy, time.Now().Add(inviteTTL))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invite", "details": err.Error()})
		return
	}
	auditCtx(c, db, "member.invited", req.Email, map[string]any{"role": req.Role})
	// The token is returned once so the admin can share an invite link.
	c.JSON(http.StatusOK, gin.H{"invited": true, "email": req.Email, "role": req.Role, "invite_token": token})
}

func changeRole(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)
	actorRole := c.GetString(ctxOrgRole)
	targetID := c.Param("userId")

	var req struct {
		Role string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if _, ok := roleRank[req.Role]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be owner, admin, member, or viewer"})
		return
	}
	oldRole := currentRole(ctx, db, orgID, targetID)
	// Only an owner can grant or revoke the owner role.
	if (req.Role == "owner" || oldRole == "owner") && actorRole != "owner" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only an owner can change owner roles"})
		return
	}
	// Never leave the org without an owner.
	if oldRole == "owner" && req.Role != "owner" && ownerCount(ctx, db, orgID) <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization must have at least one owner"})
		return
	}

	res, err := db.ExecContext(ctx,
		`UPDATE org_members SET role = $3 WHERE org_id = $1 AND user_id = $2`, orgID, targetID, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change role"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}
	auditCtx(c, db, "member.role_changed", targetID, map[string]any{"from": oldRole, "to": req.Role})
	c.JSON(http.StatusOK, gin.H{"user_id": targetID, "role": req.Role})
}

func removeMember(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)
	actorRole := c.GetString(ctxOrgRole)
	targetID := c.Param("userId")

	target := currentRole(ctx, db, orgID, targetID)
	if target == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}
	if target == "owner" && actorRole != "owner" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only an owner can remove an owner"})
		return
	}
	if target == "owner" && ownerCount(ctx, db, orgID) <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization must have at least one owner"})
		return
	}

	if _, err := db.ExecContext(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, targetID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove member"})
		return
	}
	auditCtx(c, db, "member.removed", targetID, map[string]any{"role": target})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// acceptInvite lets an already-authenticated user join an org from an invite token.
func acceptInvite(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	userID := c.GetString(ctxUserID)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}
	orgID, role, ok := redeemInvite(ctx, db, req.Token, userID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invite"})
		return
	}
	_, actorLabel := ctxActor(c, db)
	recordAudit(ctx, db, orgID, userID, actorLabel, "member.invite_accepted", "", map[string]any{"role": role}, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"org_id": orgID, "role": role})
}

// redeemInvite validates a token, adds the user to the org with the invite's
// role, and marks it accepted. Returns ok=false on any failure.
func redeemInvite(ctx context.Context, db *sql.DB, token, userID string) (orgID, role string, ok bool) {
	hash := infra.HashSessionToken(token)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = tx.Rollback() }()

	var inviteID string
	err = tx.QueryRowContext(ctx, `
		SELECT id, org_id, role FROM org_invites
		WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
		FOR UPDATE
	`, hash).Scan(&inviteID, &orgID, &role)
	if err != nil {
		return "", "", false
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role
	`, orgID, userID, role); err != nil {
		return "", "", false
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE org_invites SET accepted_at = now() WHERE id = $1`, inviteID); err != nil {
		return "", "", false
	}
	if err := tx.Commit(); err != nil {
		return "", "", false
	}
	return orgID, role, true
}

func currentRole(ctx context.Context, db dbExec, orgID, userID string) string {
	var role string
	_ = db.QueryRowContext(ctx, `SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&role)
	return role
}

func ownerCount(ctx context.Context, db dbExec, orgID string) int {
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'`, orgID).Scan(&n)
	return n
}

// dbExec is the subset of *sql.DB used by the small role helpers (also satisfied
// by *sql.Tx if ever needed).
type dbExec interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
