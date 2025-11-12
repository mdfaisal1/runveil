package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"

	"runveil/pkg/infra"
)

func NewMigrateCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "migrate [up|down|status]",
		Short: "Run Postgres migrations",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := args[0]

			// Load environment config
			infra.MustLoad()
			pgURL := os.Getenv("POSTGRES_URL") // resolved by MustLoad()

			db, err := sql.Open("pgx", pgURL)
			goose.SetLogger(log.New(os.Stdout, "goose: ", 0))
			if err := goose.SetDialect("postgres"); err != nil {
				return fmt.Errorf("goose dialect: %w", err)
			}
			if err != nil {
				return fmt.Errorf("opening postgres: %w", err)
			}
			defer db.Close()

			// default migrations directory if not passed
			if dir == "" {
				dir = defaultMigrationsDir()
			}
			if _, err := os.Stat(dir); err != nil {
				return fmt.Errorf("migrations dir not found: %s", dir)
			}

			// Run goose commands
			switch action {
			case "up":
				return goose.Up(db, dir)
			case "down":
				return goose.Down(db, dir)
			case "status":
				return goose.Status(db, dir)
			default:
				return fmt.Errorf("unknown action %q (use up|down|status)", action)
			}
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "migrations directory (defaults to deploy/compose/migrations/postgres)")
	return cmd
}

func defaultMigrationsDir() string {
	wd, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		p := filepath.Join(wd, "deploy", "compose", "migrations", "postgres")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		wd = filepath.Dir(wd)
	}
	// fallback if launched from repo root
	return "deploy/compose/migrations/postgres"
}
