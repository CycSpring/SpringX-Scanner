package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	appName    = "SpringX"
	appVersion = "v0.1.0-mvp"
)

var rootCmd = &cobra.Command{
	Use:     "springx",
	Short:   "SpringX security scanner",
	Version: appVersion,
}

// Execute runs the command line entrypoint.
func Execute() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("%s %s\n", appName, appVersion))
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
