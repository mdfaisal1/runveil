package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestLinkOrCreateOIDCUser exercises the security-critical SSO linking matrix
// against a real database. Everything runs inside a transaction that is rolled
// back, so it never mutates the dev DB. Skipped when POSTGRES_URL is unset.
func TestLinkOrCreateOIDCUser(t *testing.T) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		t.Skip("POSTGRES_URL not set; skipping SSO linking integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Skipf("database unreachable: %v", err)
	}

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // intentional: never commit, keep DB clean

	// Fixtures (all inside the rolled-back tx).
	var orgID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO organizations (slug, name) VALUES ('oidc-test-org', 'OIDC Test') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	var provID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO oidc_providers (org_id, domain, issuer, client_id, client_secret, default_role)
		 VALUES ($1, 'oidctest.example', 'https://issuer.example', 'cid', 'sec', 'member') RETURNING id`,
		orgID,
	).Scan(&provID); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	prov := &oidcProviderRow{ID: provID, OrgID: orgID, DefaultRole: "member"}

	var existingID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO users (email, name, password_hash) VALUES ('alice@oidctest.example', 'Alice', 'bcrypt-hash') RETURNING id`,
	).Scan(&existingID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// (a) Unverified email must be rejected even when the account exists — the
	//     anti-takeover rule. No linking, no creation.
	if _, err := linkOrCreateOIDCUser(ctx, tx, prov, "sub-alice", "alice@oidctest.example", "Alice", false); !errors.Is(err, errEmailNotVerified) {
		t.Fatalf("unverified+existing: want errEmailNotVerified, got %v", err)
	}

	// (b) Verified email matching an existing user → link (return that user) and
	//     ensure org membership at the provider's default role.
	uid, err := linkOrCreateOIDCUser(ctx, tx, prov, "sub-alice", "alice@oidctest.example", "Alice", true)
	if err != nil {
		t.Fatalf("verified+existing: %v", err)
	}
	if uid != existingID {
		t.Fatalf("verified+existing: want link to %s, got %s", existingID, uid)
	}
	if role := currentRole(ctx, tx, orgID, uid); role != "member" {
		t.Fatalf("verified+existing: want membership role 'member', got %q", role)
	}

	// (c) Known (provider, subject) → reuse the same user (no verified email
	//     needed, identity already trusted).
	uid2, err := linkOrCreateOIDCUser(ctx, tx, prov, "sub-alice", "", "", false)
	if err != nil {
		t.Fatalf("known sub: %v", err)
	}
	if uid2 != existingID {
		t.Fatalf("known sub: want %s, got %s", existingID, uid2)
	}

	// (d) New verified email with no existing account → create a fresh SSO-only
	//     user (NULL password) and add to the org.
	uid3, err := linkOrCreateOIDCUser(ctx, tx, prov, "sub-bob", "bob@oidctest.example", "Bob", true)
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	if uid3 == "" || uid3 == existingID {
		t.Fatalf("new user: expected a fresh user id, got %q", uid3)
	}
	var pw sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = $1`, uid3).Scan(&pw); err != nil {
		t.Fatalf("load new user: %v", err)
	}
	if pw.Valid {
		t.Fatal("new SSO user should have a NULL password_hash")
	}
	if role := currentRole(ctx, tx, orgID, uid3); role != "member" {
		t.Fatalf("new user: want membership role 'member', got %q", role)
	}
}
