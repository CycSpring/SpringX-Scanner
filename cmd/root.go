package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "SpringX"

// appVersion and buildTime can be overridden at link time via -ldflags:
//
//	go build -ldflags "-X 'github.com/CycSpring/SpringX-Scanner/cmd.appVersion=v1.0.0' \
//	  -X 'github.com/CycSpring/SpringX-Scanner/cmd.buildTime=2026-06-26T16:00:00'" .
var (
	appVersion = "v0.1.0-mvp"
	buildTime  = "unknown"
)

var rootCmd = &cobra.Command{
	Use:     "springx",
	Short:   "SpringX security scanner",
	Version: appVersion,
}

// Execute runs the command line entrypoint.
func Execute() {
	versionLine := appName + " " + appVersion
	if buildTime != "" && buildTime != "unknown" {
		versionLine += "  (built " + buildTime + ")"
	}
	rootCmd.SetVersionTemplate(versionLine + "\n")
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
