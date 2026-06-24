// services/api/identity.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mdfaisal1/runveil/pkg/infra"
)

// Context keys the auth middlewares attach to the request.
const (
	ctxUserID  = "user_id"
	ctxOrgID   = "org_id"
	ctxOrgRole = "org_role"
)

// sessionTTL is how long a browser session stays valid after login.
const sessionTTL = 14 * 24 * time.Hour

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// caller is the resolved identity behind a request, from either a browser
// session cookie or a Bearer API key. OrgID is the tenant the request acts on.
type caller struct {
	UserID string // "" for API-key callers
	OrgID  string
	Role   string // org role for sessions; "" for API keys
	ViaKey bool
}

// resolveCaller authenticates the request from a session cookie first, then a
// Bearer API key. Returns (nil, nil) when no credential is present.
func resolveCaller(c *gin.Context, db *sql.DB) (*caller, error) {
	ctx := c.Request.Context()

	// 1) Browser session cookie.
	if tok, _ := c.Cookie(infra.SessionCookieName); strings.TrimSpace(tok) != "" {
		hash := infra.HashSessionToken(tok)
		var (
			userID string
			orgID  sql.NullString
		)
		err := db.QueryRowContext(ctx, `
			SELECT user_id, org_id FROM sessions
			WHERE token_hash = $1 AND expires_at > now()
		`, hash).Scan(&userID, &orgID)
		if err == nil {
			cl := &caller{UserID: userID}
			if orgID.Valid {
				cl.OrgID = orgID.String
				_ = db.QueryRowContext(ctx,
					`SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2`,
					cl.OrgID, userID).Scan(&cl.Role)
			}
			_, _ = db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1`, hash)
			return cl, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	// 2) Bearer API key (CLI / CI).
	if tok := bearerToken(c); tok != "" {
		hash := infra.HashAPIKey(tok)
		var (
			id    string
			scope string
			orgID sql.NullString
		)
		err := db.QueryRowContext(ctx, `
			SELECT id, scope, org_id FROM api_keys
			WHERE key_hash = $1 AND revoked_at IS NULL
		`, hash).Scan(&id, &scope, &orgID)
		if err == nil {
			cl := &caller{ViaKey: true}
			if orgID.Valid {
				cl.OrgID = orgID.String
			}
			_, _ = db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
			c.Set(ctxAPIKeyID, id)
			c.Set(ctxAPIKeyScope, scope)
			return cl, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	return nil, nil
}

// stashCaller copies the resolved identity onto the gin context for handlers.
func stashCaller(c *gin.Context, cl *caller) {
	c.Set(ctxOrgID, cl.OrgID)
	if cl.UserID != "" {
		c.Set(ctxUserID, cl.UserID)
	}
	if cl.Role != "" {
		c.Set(ctxOrgRole, cl.Role)
	}
}

// requireAuth guards routes that act on the caller's current org but carry no
// :slug (e.g. listing projects, org/member management). 401 if unauthenticated.
func requireAuth(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, err := resolveCaller(c, db)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth check failed"})
			return
		}
		if cl == nil || cl.OrgID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		stashCaller(c, cl)
		c.Next()
	}
}

// requireProjectOrg guards every /v1/projects/:slug/... route: the slug's project
// must belong to the caller's org. Project slugs are globally unique, so this one
// check makes the existing slug-keyed queries tenant-safe. A missing project and a
// cross-tenant project both return 404 — we never leak existence across tenants.
func requireProjectOrg(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, err := resolveCaller(c, db)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth check failed"})
			return
		}
		if cl == nil || cl.OrgID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		slug := c.Param("slug")
		var projOrg string
		err = db.QueryRowContext(c.Request.Context(),
			`SELECT org_id FROM projects WHERE slug = $1`, slug).Scan(&projOrg)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && projOrg != cl.OrgID) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "project not found"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth check failed"})
			return
		}
		stashCaller(c, cl)
		c.Next()
	}
}

// cookieSecure reports whether the session cookie should carry the Secure flag.
// Off by default for local http dev; set RUNVEIL_COOKIE_SECURE=1 behind TLS.
func cookieSecure() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("RUNVEIL_COOKIE_SECURE")))
	return v == "1" || v == "true" || v == "yes"
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(infra.SessionCookieName, token, maxAge, "/", "", cookieSecure(), true /* httpOnly */)
}

// ---------- request/response DTOs ----------

type signupRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	OrgName  string `json:"org_name"`     // optional; defaults to the user's name/email
	Invite   string `json:"invite_token"` // optional; join an existing org instead of creating one
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type meResponse struct {
	UserID  string         `json:"user_id"`
	Email   string         `json:"email"`
	Name    string         `json:"name"`
	OrgID   string         `json:"org_id"`
	OrgSlug string         `json:"org_slug"`
	OrgName string         `json:"org_name"`
	Role    string         `json:"role"`
	Orgs    []membershipVW `json:"orgs"`
}

type membershipVW struct {
	OrgID string `json:"org_id"`
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// registerIdentity wires signup/login/logout/me/switch-org.
func registerIdentity(r *gin.Engine, db *sql.DB) {
	r.POST("/v1/auth/signup", func(c *gin.Context) { handleSignup(c, db) })
	r.POST("/v1/auth/login", func(c *gin.Context) { handleLogin(c, db) })
	r.POST("/v1/auth/logout", func(c *gin.Context) { handleLogout(c, db) })
	r.GET("/v1/auth/me", requireAuth(db), func(c *gin.Context) { handleMe(c, db) })
	r.POST("/v1/auth/switch-org", requireAuth(db), func(c *gin.Context) { handleSwitchOrg(c, db) })
}

func handleSignup(c *gin.Context, db *sql.DB) {
	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if !emailRe.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid email is required"})
		return
	}
	pwHash, err := infra.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
		return
	}
	defer func() { _ = tx.Rollback() }()

	var userID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id
	`, req.Email, req.Name, pwHash).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "an account with that email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
		return
	}

	var (
		orgID   string
		orgSlug string
	)
	if inv := strings.TrimSpace(req.Invite); inv != "" {
		// Redeem an invite: join the inviting org with the invite's role. The
		// role comes from the invite row, never from the request body. Redeemed
		// in this same tx so the just-created user is visible to the FK.
		var inviteID, role string
		err := tx.QueryRowContext(ctx, `
			SELECT id, org_id, role FROM org_invites
			WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
			FOR UPDATE
		`, infra.HashSessionToken(inv)).Scan(&inviteID, &orgID, &role)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invite"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
			return
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)`,
			orgID, userID, role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
			return
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE org_invites SET accepted_at = now() WHERE id = $1`, inviteID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
			return
		}
		_ = tx.QueryRowContext(ctx, `SELECT slug FROM organizations WHERE id = $1`, orgID).Scan(&orgSlug)
	} else {
		// No invite: create the user's own org and make them its owner.
		orgName := strings.TrimSpace(req.OrgName)
		if orgName == "" {
			if req.Name != "" {
				orgName = req.Name + "'s Org"
			} else {
				orgName = req.Email
			}
		}
		orgSlug = uniqueOrgSlug(ctx, tx, slugify(orgName))
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO organizations (slug, name) VALUES ($1, $2) RETURNING id`,
			orgSlug, orgName).Scan(&orgID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
			return
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')`,
			orgID, userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
			return
		}
	}

	token, err := createSessionTx(ctx, tx, userID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
		return
	}

	setSessionCookie(c, token, int(sessionTTL.Seconds()))
	c.JSON(http.StatusCreated, gin.H{"user_id": userID, "org_id": orgID, "org_slug": orgSlug})
}

func handleLogin(c *gin.Context, db *sql.DB) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	ctx := c.Request.Context()
	var (
		userID string
		pwHash sql.NullString
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE lower(email) = $1`, req.Email).Scan(&userID, &pwHash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !infra.VerifyPassword(pwHash.String, req.Password)) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	orgID := primaryOrgID(ctx, db, userID)
	token, err := createSession(ctx, db, userID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}
	setSessionCookie(c, token, int(sessionTTL.Seconds()))
	c.JSON(http.StatusOK, gin.H{"user_id": userID, "org_id": orgID})
}

func handleLogout(c *gin.Context, db *sql.DB) {
	if tok, _ := c.Cookie(infra.SessionCookieName); strings.TrimSpace(tok) != "" {
		_, _ = db.ExecContext(c.Request.Context(),
			`DELETE FROM sessions WHERE token_hash = $1`, infra.HashSessionToken(tok))
	}
	setSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleMe(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	userID := c.GetString(ctxUserID)
	if userID == "" {
		// API-key caller hit a user-only route.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
		return
	}
	orgID := c.GetString(ctxOrgID)

	var out meResponse
	out.UserID = userID
	out.OrgID = orgID
	out.Role = c.GetString(ctxOrgRole)

	if err := db.QueryRowContext(ctx,
		`SELECT email, name FROM users WHERE id = $1`, userID).Scan(&out.Email, &out.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}
	if orgID != "" {
		_ = db.QueryRowContext(ctx,
			`SELECT slug, name FROM organizations WHERE id = $1`, orgID).Scan(&out.OrgSlug, &out.OrgName)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT o.id, o.slug, o.name, m.role
		FROM org_members m JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = $1 ORDER BY o.name
	`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var m membershipVW
			if err := rows.Scan(&m.OrgID, &m.Slug, &m.Name, &m.Role); err == nil {
				out.Orgs = append(out.Orgs, m)
			}
		}
	}
	c.JSON(http.StatusOK, out)
}

func handleSwitchOrg(c *gin.Context, db *sql.DB) {
	var req struct {
		OrgID string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.OrgID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id is required"})
		return
	}
	ctx := c.Request.Context()
	userID := c.GetString(ctxUserID)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
		return
	}

	// Verify membership before switching.
	var role string
	err := db.QueryRowContext(ctx,
		`SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2`, req.OrgID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a member of that organization"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "switch failed"})
		return
	}
	if tok, _ := c.Cookie(infra.SessionCookieName); strings.TrimSpace(tok) != "" {
		_, _ = db.ExecContext(ctx, `UPDATE sessions SET org_id = $1 WHERE token_hash = $2`,
			req.OrgID, infra.HashSessionToken(tok))
	}
	c.JSON(http.StatusOK, gin.H{"org_id": req.OrgID, "role": role})
}

// ---------- session + org helpers ----------

func createSession(ctx context.Context, db *sql.DB, userID, orgID string) (string, error) {
	token, hash, err := infra.GenerateSessionToken()
	if err != nil {
		return "", err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, org_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, hash, userID, nullableStr(orgID), time.Now().Add(sessionTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

func createSessionTx(ctx context.Context, tx *sql.Tx, userID, orgID string) (string, error) {
	token, hash, err := infra.GenerateSessionToken()
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, org_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, hash, userID, nullableStr(orgID), time.Now().Add(sessionTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

// primaryOrgID returns the user's first org (owner preferred), or "" if none.
func primaryOrgID(ctx context.Context, db *sql.DB, userID string) string {
	var orgID string
	_ = db.QueryRowContext(ctx, `
		SELECT org_id FROM org_members WHERE user_id = $1
		ORDER BY (role = 'owner') DESC, created_at ASC LIMIT 1
	`, userID).Scan(&orgID)
	return orgID
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "duplicate") || strings.Contains(s, "sqlstate 23505")
}

var slugStripRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugStripRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "org"
	}
	return s
}

// uniqueOrgSlug returns base, or base-2, base-3… until it doesn't collide.
func uniqueOrgSlug(ctx context.Context, tx *sql.Tx, base string) string {
	slug := base
	for i := 2; ; i++ {
		var exists bool
		_ = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)`, slug).Scan(&exists)
		if !exists {
			return slug
		}
		slug = base + "-" + strconv.Itoa(i)
	}
}
