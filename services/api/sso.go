// services/api/sso.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/mdfaisal1/runveil/pkg/infra"
	"golang.org/x/oauth2"
)

// errEmailNotVerified blocks linking/creating an account from an OIDC identity
// whose email the provider hasn't asserted as verified (anti-takeover).
var errEmailNotVerified = errors.New("provider did not assert a verified email; cannot sign in via SSO")

const oidcStateTTL = 10 * time.Minute

// oidcRedirectURL is where the IdP sends the user back. It must be registered
// with the provider and live on the dashboard origin so the session cookie is
// usable after the redirect. Defaults to the dev proxy path.
func oidcRedirectURL() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_OIDC_REDIRECT_URL")); v != "" {
		return v
	}
	return "http://localhost:4200/v1/auth/oidc/callback"
}

// oidcSuccessURL is where we send the browser after a successful SSO login.
func oidcSuccessURL() string {
	if v := strings.TrimSpace(os.Getenv("RUNVEIL_OIDC_SUCCESS_URL")); v != "" {
		return v
	}
	return "http://localhost:4200/projects"
}

func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

type oidcProviderRow struct {
	ID           string
	OrgID        string
	Domain       string
	Issuer       string
	ClientID     string
	ClientSecret string
	DefaultRole  string
}

func providerByDomain(ctx context.Context, db *sql.DB, domain string) (*oidcProviderRow, error) {
	var p oidcProviderRow
	err := db.QueryRowContext(ctx, `
		SELECT id, org_id, domain, issuer, client_id, client_secret, default_role
		FROM oidc_providers WHERE lower(domain) = $1
	`, strings.ToLower(domain)).Scan(
		&p.ID, &p.OrgID, &p.Domain, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.DefaultRole)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// registerSSO wires per-org OIDC provider config + the login/callback flow.
func registerSSO(r *gin.Engine, db *sql.DB) {
	// Admin/owner registers (upserts) their org's IdP.
	r.PUT("/v1/org/oidc", requireAuth(db), requireRole("admin"), func(c *gin.Context) { putOIDCConfig(c, db) })
	r.GET("/v1/org/oidc", requireAuth(db), requireRole("admin"), func(c *gin.Context) { getOIDCConfig(c, db) })

	// Browser SSO flow.
	r.POST("/v1/auth/oidc/start", func(c *gin.Context) { oidcStart(c, db) })
	r.GET("/v1/auth/oidc/callback", func(c *gin.Context) { oidcCallback(c, db) })
}

func putOIDCConfig(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)
	var req struct {
		Domain       string `json:"domain"`
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		DefaultRole  string `json:"default_role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.Domain == "" || req.Issuer == "" || req.ClientID == "" || req.ClientSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain, issuer, client_id, client_secret are required"})
		return
	}
	if req.DefaultRole == "" {
		req.DefaultRole = "member"
	}
	if r := strings.ToLower(req.DefaultRole); r != "admin" && r != "member" && r != "viewer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "default_role must be admin, member, or viewer"})
		return
	}

	// Encrypt the client secret at rest (AES-GCM; see infra.EncryptSecret).
	encSecret, err := infra.EncryptSecret(req.ClientSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to secure SSO secret"})
		return
	}

	// One provider per org; a domain maps to one org globally.
	_, err = db.ExecContext(ctx, `
		INSERT INTO oidc_providers (org_id, domain, issuer, client_id, client_secret, default_role)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id) DO UPDATE SET
			domain = EXCLUDED.domain, issuer = EXCLUDED.issuer,
			client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
			default_role = EXCLUDED.default_role, updated_at = now()
	`, orgID, req.Domain, req.Issuer, req.ClientID, encSecret, strings.ToLower(req.DefaultRole))
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "that email domain is already claimed by another organization"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save SSO config"})
		return
	}
	auditCtx(c, db, "sso.configured", req.Domain, map[string]any{"issuer": req.Issuer, "default_role": strings.ToLower(req.DefaultRole)})
	c.JSON(http.StatusOK, gin.H{"ok": true, "domain": req.Domain})
}

func getOIDCConfig(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	orgID := c.GetString(ctxOrgID)
	var (
		domain, issuer, clientID, role string
	)
	err := db.QueryRowContext(ctx, `
		SELECT domain, issuer, client_id, default_role FROM oidc_providers WHERE org_id = $1
	`, orgID).Scan(&domain, &issuer, &clientID, &role)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusOK, gin.H{"configured": false})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load SSO config"})
		return
	}
	// Never return the client secret.
	c.JSON(http.StatusOK, gin.H{
		"configured": true, "domain": domain, "issuer": issuer,
		"client_id": clientID, "default_role": role,
	})
}

// oidcStart resolves the IdP for the email's domain and returns the IdP
// authorization URL for the SPA to navigate to. {sso:false} means use password.
func oidcStart(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}
	domain := emailDomain(strings.ToLower(strings.TrimSpace(req.Email)))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid email is required"})
		return
	}
	prov, err := providerByDomain(ctx, db, domain)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusOK, gin.H{"sso": false})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve SSO"})
		return
	}

	oidcProvider, err := oidc.NewProvider(ctx, prov.Issuer)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not reach identity provider"})
		return
	}
	state, _, _ := infra.GenerateSessionToken()
	nonce, _, _ := infra.GenerateSessionToken()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO oidc_states (state, provider_id, nonce, expires_at) VALUES ($1, $2, $3, $4)
	`, state, prov.ID, nonce, time.Now().Add(oidcStateTTL)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start SSO"})
		return
	}

	secret, err := infra.DecryptSecret(prov.ClientSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO secret could not be read (check RUNVEIL_SECRET_KEY)"})
		return
	}
	conf := oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: secret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  oidcRedirectURL(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	authURL := conf.AuthCodeURL(state, oidc.Nonce(nonce))
	c.JSON(http.StatusOK, gin.H{"sso": true, "auth_url": authURL})
}

// oidcCallback completes the code exchange, verifies the ID token, links or
// creates the user, opens a session, and redirects to the dashboard.
func oidcCallback(c *gin.Context, db *sql.DB) {
	ctx := c.Request.Context()
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code/state"})
		return
	}

	// Consume the state (one-time) and recover provider + nonce.
	var (
		providerID string
		nonce      string
	)
	err := db.QueryRowContext(ctx, `
		DELETE FROM oidc_states WHERE state = $1 AND expires_at > now()
		RETURNING provider_id, nonce
	`, state).Scan(&providerID, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired SSO state"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO callback failed"})
		return
	}

	var prov oidcProviderRow
	if err := db.QueryRowContext(ctx, `
		SELECT id, org_id, domain, issuer, client_id, client_secret, default_role
		FROM oidc_providers WHERE id = $1
	`, providerID).Scan(&prov.ID, &prov.OrgID, &prov.Domain, &prov.Issuer,
		&prov.ClientID, &prov.ClientSecret, &prov.DefaultRole); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO provider not found"})
		return
	}

	oidcProvider, err := oidc.NewProvider(ctx, prov.Issuer)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not reach identity provider"})
		return
	}
	secret, err := infra.DecryptSecret(prov.ClientSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO secret could not be read (check RUNVEIL_SECRET_KEY)"})
		return
	}
	conf := oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: secret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  oidcRedirectURL(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "token exchange failed"})
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		c.JSON(http.StatusBadGateway, gin.H{"error": "no id_token in response"})
		return
	}
	idTok, err := oidcProvider.Verifier(&oidc.Config{ClientID: prov.ClientID}).Verify(ctx, rawID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "id_token verification failed"})
		return
	}
	if idTok.Nonce != nonce {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "nonce mismatch"})
		return
	}
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idTok.Claims(&claims); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not parse identity claims"})
		return
	}

	// Link/create + session in one tx.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO callback failed"})
		return
	}
	defer func() { _ = tx.Rollback() }()

	userID, err := linkOrCreateOIDCUser(ctx, tx, &prov, claims.Sub, claims.Email, claims.Name, claims.EmailVerified)
	if err != nil {
		if errors.Is(err, errEmailNotVerified) {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO login failed"})
		return
	}
	token, err := createSessionTx(ctx, tx, userID, prov.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO login failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SSO login failed"})
		return
	}

	setSessionCookie(c, token, int(sessionTTL.Seconds()))
	recordAudit(ctx, db, prov.OrgID, userID, strings.ToLower(strings.TrimSpace(claims.Email)),
		"auth.sso_login", prov.Domain, nil, c.ClientIP())
	c.Redirect(http.StatusFound, oidcSuccessURL())
}

// linkOrCreateOIDCUser resolves the Runveil user behind an OIDC identity:
//   - known (provider, subject) → that user (already trusted).
//   - else requires a verified email, then links to an existing password user
//     with that email, or creates a fresh SSO-only user.
//
// Either way the user is ensured into the provider's org with its default role.
func linkOrCreateOIDCUser(ctx context.Context, tx *sql.Tx, prov *oidcProviderRow, sub, email, name string, emailVerified bool) (string, error) {
	// 1) Already-linked identity.
	var userID string
	err := tx.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities WHERE provider_id = $1 AND subject = $2`,
		prov.ID, sub).Scan(&userID)
	if err == nil {
		if err := ensureMembership(ctx, tx, prov.OrgID, userID, prov.DefaultRole); err != nil {
			return "", err
		}
		return userID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	// Beyond here we touch accounts by email, so require a verified one.
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !emailVerified {
		return "", errEmailNotVerified
	}

	// 2) Existing password/user account with this email → link.
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email) = $1`, email).Scan(&userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if errors.Is(err, sql.ErrNoRows) {
		// 3) Create a fresh SSO-only user (no password).
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO users (email, name, password_hash) VALUES ($1, $2, NULL) RETURNING id`,
			email, name).Scan(&userID); err != nil {
			return "", err
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_identities (user_id, provider_id, subject) VALUES ($1, $2, $3)
		 ON CONFLICT (provider_id, subject) DO NOTHING`,
		userID, prov.ID, sub); err != nil {
		return "", err
	}
	if err := ensureMembership(ctx, tx, prov.OrgID, userID, prov.DefaultRole); err != nil {
		return "", err
	}
	return userID, nil
}

// ensureMembership adds the user to the org at the given role if not already a
// member; it never downgrades an existing (possibly higher) role.
func ensureMembership(ctx context.Context, tx *sql.Tx, orgID, userID, role string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (org_id, user_id) DO NOTHING
	`, orgID, userID, role)
	return err
}
