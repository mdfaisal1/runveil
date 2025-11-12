package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"runveil/pkg/infra"

	"github.com/spf13/cobra"
)

func NewDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check connectivity to Postgres/Neo4j/NATS",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cfg := infra.MustLoad()

			db, err := infra.OpenPostgres(ctx, os.Getenv("POSTGRES_URL"))
			if err != nil {
				return err
			}
			defer db.Close()

			neo, err := infra.OpenNeo4j(ctx, os.Getenv("NEO4J_URL"), cfg.Neo4jUser, cfg.Neo4jPass)
			if err != nil {
				return err
			}
			defer neo.Close(ctx)

			nc, err := infra.ConnectNATS(os.Getenv("NATS_URL"))
			if err != nil {
				return err
			}
			defer nc.Drain()

			fmt.Println("✅ All backends connected successfully!")
			fmt.Println("  • Postgres:", os.Getenv("POSTGRES_URL"))
			fmt.Println("  • Neo4j:", os.Getenv("NEO4J_URL"))
			fmt.Println("  • NATS:", os.Getenv("NATS_URL"))
			fmt.Println("  • Time:", time.Now().Format(time.RFC822))
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(NewDoctorCmd())
}
