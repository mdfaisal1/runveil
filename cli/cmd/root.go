package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keystone",
	Short: "Keystone CLI",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Register subcommands that don't self-register
	rootCmd.AddCommand(NewMigrateCmd())
	// If your scan command self-registers in scan.go via init(), no need to add it here.
}
