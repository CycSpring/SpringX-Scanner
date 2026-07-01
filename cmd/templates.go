package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/CycSpring/SpringX-Scanner/internal/scan"
	"github.com/spf13/cobra"
)

type templatesPullOptions struct {
	dir    string
	repo   string
	branch string
	force  bool
	depth  int
}

var templatesPullOpts templatesPullOptions

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "Manage Nuclei POC templates",
}

var templatesPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull official Nuclei templates from GitHub into the local template directory",
	Long: "Clone (or update) the official projectdiscovery/nuclei-templates " +
		"repository into the local POC template directory so scans have " +
		"templates to run. By default it writes to ./pocs/nuclei, which is " +
		"the directory `springx scan` uses when --nuclei-template-dir is not " +
		"set. A shallow clone (depth=1) keeps the download small; re-running " +
		"pull updates an existing checkout.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		dir := templatesPullOpts.dir
		if dir == "" {
			dir = filepath.Join(wd, "pocs", "nuclei")
		}

		logf := func(format string, args ...any) {
			fmt.Fprintf(os.Stdout, format+"\n", args...)
		}
		res, err := scan.PullTemplates(ctx, scan.PullTemplatesOptions{
			Dir:    dir,
			Repo:   templatesPullOpts.repo,
			Branch: templatesPullOpts.branch,
			Force:  templatesPullOpts.force,
			Depth:  templatesPullOpts.depth,
			Logf:   logf,
		})
		if err != nil {
			return err
		}
		fmt.Printf("[INF] 模板就绪: action=%s dir=%s commit=%s count=%d\n", res.Action, res.Dir, res.Commit, res.Count)
		fmt.Printf("[INF] 版本: %s\n", res.Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(templatesCmd)
	templatesCmd.AddCommand(templatesPullCmd)

	templatesPullCmd.Flags().StringVar(&templatesPullOpts.dir, "dir", "", "target template directory (default: ./pocs/nuclei)")
	templatesPullCmd.Flags().StringVar(&templatesPullOpts.repo, "repo", "", "git remote URL (default: official nuclei-templates)")
	templatesPullCmd.Flags().StringVar(&templatesPullOpts.branch, "branch", "main", "branch to track")
	templatesPullCmd.Flags().BoolVar(&templatesPullOpts.force, "force", false, "remove an existing directory before cloning")
	templatesPullCmd.Flags().IntVar(&templatesPullOpts.depth, "depth", 1, "clone depth (0 = full history)")
}
