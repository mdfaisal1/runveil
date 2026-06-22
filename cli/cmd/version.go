package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build metadata. Overridable at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/mdfaisal1/runveil/cli/cmd.version=v0.1.0 \
//	  -X github.com/mdfaisal1/runveil/cli/cmd.commit=$(git rev-parse --short HEAD) \
//	  -X github.com/mdfaisal1/runveil/cli/cmd.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
//	  ./cmd/runveil
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// NewVersionCmd prints the CLI version and build metadata.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the runveil version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("runveil %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
			fmt.Printf("  go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
