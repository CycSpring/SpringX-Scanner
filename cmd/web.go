package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/CycSpring/SpringX-Scanner/internal/web"
	"github.com/spf13/cobra"
)

type webOptions struct {
	addr    string
	port    int
	workDir string
}

var webOpts webOptions

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Run the SpringX WebUI server",
	Long: "Run a long-running WebUI HTTP server that drives `springx scan --jsonl-only` " +
		"child processes and streams their JSONL events to browsers over Server-Sent " +
		"Events. The scanner core is not modified; the WebUI consumes the " +
		"springx.events.v1 protocol emitted on the child's stdout.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		addr := fmt.Sprintf("%s:%d", webOpts.addr, webOpts.port)
		srv, err := web.NewServer(web.Options{
			Addr:    addr,
			WorkDir: webOpts.workDir,
		})
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return srv.Start(ctx)
	},
}

func init() {
	rootCmd.AddCommand(webCmd)

	webCmd.Flags().StringVar(&webOpts.addr, "addr", "127.0.0.1", "listen address")
	webCmd.Flags().IntVar(&webOpts.port, "port", 8849, "listen port")
	webCmd.Flags().StringVar(&webOpts.workDir, "work-dir", "", "working directory for scan reports (default: current directory)")
}
