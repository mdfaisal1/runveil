package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/mdfaisal1/runveil/pkg/infra"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
)

// NewAdminCmd is the parent for operator/bootstrap commands. Like `migrate` and
// `keys`, these talk to Postgres directly (POSTGRES_URL) — this is the path that
// seeds the first owner before any browser login exists (chicken-and-egg).
func NewAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Operator commands: bootstrap the first org + owner user",
	}
	cmd.AddCommand(newAdminBootstrapCmd())
	return cmd
}

func newAdminBootstrapCmd() *cobra.Command {
	var (
		email    string
		password string
		name     string
		orgName  string
		orgSlug  string
	)

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Create (or reuse) an organization and an owner user",
		RunE: func(cmd *cobra.Command, args []string) error {
			email = strings.ToLower(strings.TrimSpace(email))
			if email == "" || strings.TrimSpace(password) == "" {
				return fmt.Errorf("--email and --password are required")
			}
			if orgName == "" {
				orgName = "Default Organization"
			}
			if orgSlug == "" {
				orgSlug = "default"
			}

			pwHash, err := infra.HashPassword(password)
			if err != nil {
				return err
			}

			infra.MustLoad()
			pgURL := os.Getenv("POSTGRES_URL")
			if pgURL == "" {
				return fmt.Errorf("POSTGRES_URL not set")
			}
			db, err := sql.Open("pgx", pgURL)
			if err != nil {
				return fmt.Errorf("opening postgres: %w", err)
			}
			defer db.Close()

			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()

			// Org: reuse by slug if present, else create.
			var orgID string
			err = tx.QueryRowContext(ctx, `SELECT id FROM organizations WHERE slug = $1`, orgSlug).Scan(&orgID)
			if err == sql.ErrNoRows {
				if err := tx.QueryRowContext(ctx,
					`INSERT INTO organizations (slug, name) VALUES ($1, $2) RETURNING id`,
					orgSlug, orgName).Scan(&orgID); err != nil {
					return fmt.Errorf("creating org: %w", err)
				}
			} else if err != nil {
				return fmt.Errorf("looking up org: %w", err)
			}

			// User: create (fail if email already exists).
			var userID string
			err = tx.QueryRowContext(ctx,
				`INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id`,
				email, name, pwHash).Scan(&userID)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "sqlstate 23505") {
					return fmt.Errorf("a user with email %q already exists", email)
				}
				return fmt.Errorf("creating user: %w", err)
			}

			// Membership as owner.
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')
				 ON CONFLICT (org_id, user_id) DO UPDATE SET role = 'owner'`,
				orgID, userID); err != nil {
				return fmt.Errorf("adding membership: %w", err)
			}

			if err := tx.Commit(); err != nil {
				return err
			}

			fmt.Println("✅ Bootstrap complete.")
			fmt.Printf("   org:   %s (%s)\n", orgName, orgSlug)
			fmt.Printf("   owner: %s\n", email)
			fmt.Println("\nLog in at the dashboard with these credentials.")
			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "owner email (required)")
	cmd.Flags().StringVar(&password, "password", "", "owner password, min 8 chars (required)")
	cmd.Flags().StringVar(&name, "name", "", "owner display name")
	cmd.Flags().StringVar(&orgName, "org-name", "", "organization name (default \"Default Organization\")")
	cmd.Flags().StringVar(&orgSlug, "org-slug", "", "organization slug (default \"default\")")
	return cmd
}
