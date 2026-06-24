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

// NewKeysCmd is the parent for API-key management. Like `migrate`, these
// subcommands talk to Postgres directly (POSTGRES_URL) rather than the API —
// this is the operator/bootstrap path that sidesteps the chicken-and-egg of
// needing a key to mint the first key.
func NewKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage API keys for the Runveil API",
	}
	cmd.AddCommand(newKeysCreateCmd())
	return cmd
}

func newKeysCreateCmd() *cobra.Command {
	var (
		projectSlug string
		orgSlug     string
		name        string
		scope       string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a new API key (printed once) and store its hash in Postgres",
		RunE: func(cmd *cobra.Command, args []string) error {
			scope = strings.TrimSpace(scope)
			switch scope {
			case "ingest", "read", "admin":
			default:
				return fmt.Errorf("invalid --scope %q (use ingest|read|admin)", scope)
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

			// Resolve project + org so the key is tenant-scoped. A key MUST belong
			// to an org (ingest stamps a project's org from the key). If --project
			// is given, the key inherits that project's org; otherwise resolve --org
			// (defaulting to "default").
			var (
				projectID sql.NullString
				orgID     string
			)
			if s := strings.TrimSpace(projectSlug); s != "" {
				var id, oid string
				err := db.QueryRowContext(ctx,
					`SELECT id, org_id FROM projects WHERE slug = $1`, s).Scan(&id, &oid)
				if err == sql.ErrNoRows {
					return fmt.Errorf("project %q not found", s)
				}
				if err != nil {
					return fmt.Errorf("looking up project: %w", err)
				}
				projectID = sql.NullString{String: id, Valid: true}
				orgID = oid
			} else {
				slug := strings.TrimSpace(orgSlug)
				if slug == "" {
					slug = infra.ConfigOrg() // file fallback before built-in default
				}
				if slug == "" {
					slug = "default"
				}
				err := db.QueryRowContext(ctx,
					`SELECT id FROM organizations WHERE slug = $1`, slug).Scan(&orgID)
				if err == sql.ErrNoRows {
					return fmt.Errorf("organization %q not found (run `runveil admin bootstrap` first)", slug)
				}
				if err != nil {
					return fmt.Errorf("looking up org: %w", err)
				}
			}

			plaintext, prefix, hash, err := infra.GenerateAPIKey()
			if err != nil {
				return err
			}

			var label sql.NullString
			if n := strings.TrimSpace(name); n != "" {
				label = sql.NullString{String: n, Valid: true}
			}

			if _, err := db.ExecContext(ctx, `
				INSERT INTO api_keys (project_id, org_id, name, key_hash, key_prefix, scope)
				VALUES ($1, $2, $3, $4, $5, $6)
			`, projectID, orgID, label, hash, prefix, scope); err != nil {
				return fmt.Errorf("storing api key: %w", err)
			}

			// Show the plaintext exactly once. Everything else is derived.
			fmt.Println("API key created. Store it now — it will not be shown again.")
			fmt.Println()
			fmt.Printf("  key:     %s\n", plaintext)
			fmt.Printf("  prefix:  %s\n", prefix)
			fmt.Printf("  scope:   %s\n", scope)
			if projectSlug != "" {
				fmt.Printf("  project: %s\n", projectSlug)
			}
			fmt.Println()
			fmt.Println("Use it with the CLI by exporting:")
			fmt.Printf("  export RUNVEIL_API_TOKEN=%s\n", plaintext)
			return nil
		},
	}

	cmd.Flags().StringVar(&projectSlug, "project", "", "scope the key to a project slug (optional; inherits the project's org)")
	cmd.Flags().StringVar(&orgSlug, "org", "", "org slug the key belongs to when no --project is given (default \"default\")")
	cmd.Flags().StringVar(&name, "name", "", "human-readable label for the key (e.g. ci-github)")
	cmd.Flags().StringVar(&scope, "scope", "ingest", "key scope: ingest|read|admin")
	return cmd
}
