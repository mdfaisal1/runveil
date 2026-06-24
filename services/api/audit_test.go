package main

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestAuditLogAppendOnly proves the migration-0016 guarantees against a real DB:
// UPDATE/DELETE are blocked, yet deleting an org that has audit rows still
// succeeds (the FK was dropped so the trail outlives what it logs). Runs inside a
// rolled-back transaction; expected-failure statements are isolated with
// savepoints so one aborted statement doesn't poison the rest. Skipped without DB.
func TestAuditLogAppendOnly(t *testing.T) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		t.Skip("POSTGRES_URL not set; skipping append-only integration test")
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
	defer tx.Rollback() //nolint:errcheck // intentional: keep DB clean

	var orgID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO organizations (slug, name) VALUES ('audit-immut-test', 'Immut') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	var auditID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO audit_log (org_id, actor_label, action) VALUES ($1, 'tester', 'test.event') RETURNING id`,
		orgID,
	).Scan(&auditID); err != nil {
		t.Fatalf("seed audit row (INSERT must be allowed): %v", err)
	}

	mustBlock := func(name, query string) {
		if _, err := tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
			t.Fatalf("savepoint %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, query, auditID); err == nil {
			t.Fatalf("%s: expected append-only violation, got nil error", name)
		}
		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); err != nil {
			t.Fatalf("rollback to %s: %v", name, err)
		}
	}
	mustBlock("sp_update", `UPDATE audit_log SET action = 'tampered' WHERE id = $1`)
	mustBlock("sp_delete", `DELETE FROM audit_log WHERE id = $1`)

	// The decoupling proof: deleting the org must SUCCEED (no FK cascade into
	// audit_log), and the audit row must survive it.
	if _, err := tx.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, orgID); err != nil {
		t.Fatalf("deleting an org with audit rows should succeed (FK dropped): %v", err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE id = $1`, auditID).Scan(&n); err != nil {
		t.Fatalf("count audit row: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit row should survive org deletion; found %d", n)
	}
}
