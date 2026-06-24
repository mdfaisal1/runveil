package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "runveil",
	Short:   "runveil CLI",
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Register subcommands that don't self-register
	rootCmd.AddCommand(NewMigrateCmd())
	rootCmd.AddCommand(NewKeysCmd())
	rootCmd.AddCommand(NewVersionCmd())
	rootCmd.AddCommand(NewEvidenceCmd())
	rootCmd.AddCommand(NewComponentsCmd())
	rootCmd.AddCommand(NewAdminCmd())
	// If your scan command self-registers in scan.go via init(), no need to add it here.
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(findingsCmd)

	findingsCmd.Flags().StringVar(&findingsProject, "project", "", "Project slug (required)")
	findingsCmd.Flags().StringVar(&findingsFormat, "format", "md", "Output format: md or json")
}
