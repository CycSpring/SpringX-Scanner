package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/report"
	"github.com/CycSpring/SpringX-Scanner/internal/scan"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	targetURL         string
	targetIP          string
	urlFile           string
	ipFile            string
	cyber             string
	spy               string
	ports             string
	proxy             string
	outName           string
	web               bool
	noBrowser         bool
	dbs               bool
	risk              bool
	deepScan          bool
	noPing            bool
	noPOC             bool
	noCrack           bool
	noImg             bool
	random            bool
	rdp               bool
	spyOnly           bool
	threads           int
	doneMinutes       int
	chanRatio         string
	platform          string
	size              int
	gonmapTimeout     int
	nucleiTags        string
	nucleiSeverity    string
	nucleiIDs         string
	nucleiTemplateDir string
	tempDir           string
	xrayPOCName       string
	pocConcurrency    int
	httpConcurrency   int
	httpTimeout       int
	engines           string
	logFormat         string
	jsonlOnly         bool
}

var scanOpts scanOptions

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run an authorized SpringX scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		logFormat := scanOpts.logFormat
		if scanOpts.jsonlOnly {
			logFormat = "jsonl"
		}
		logFormat = normalizedLogFormat(logFormat)
		if logFormat != "mixed" && logFormat != "jsonl" {
			return fmt.Errorf("unsupported --log-format %q, expected mixed or jsonl", logFormat)
		}
		if logFormat != "jsonl" {
			printBanner()
			printDisclaimer()
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		wd, err := os.Getwd()
		if err != nil {
			return err
		}

		templateDir := scanOpts.nucleiTemplateDir
		if templateDir == "" {
			templateDir = filepath.Join(wd, "pocs", "nuclei")
		}

		cfg := scan.Config{
			Version:         appVersion,
			WorkDir:         wd,
			TargetURL:       scanOpts.targetURL,
			TargetIP:        scanOpts.targetIP,
			URLFile:         scanOpts.urlFile,
			IPFile:          scanOpts.ipFile,
			Cyber:           scanOpts.cyber,
			Spy:             scanOpts.spy,
			Ports:           scanOpts.ports,
			Proxy:           scanOpts.proxy,
			OutName:         scanOpts.outName,
			Web:             scanOpts.web,
			NoBrowser:       scanOpts.noBrowser,
			NoPing:          scanOpts.noPing,
			NoPOC:           scanOpts.noPOC,
			Threads:         scanOpts.threads,
			DoneMinutes:     scanOpts.doneMinutes,
			ChanRatio:       scanOpts.chanRatio,
			Platform:        scanOpts.platform,
			Size:            scanOpts.size,
			GonmapTimeout:   scanOpts.gonmapTimeout,
			NucleiTags:      splitCSV(scanOpts.nucleiTags),
			NucleiSeverity:  scanOpts.nucleiSeverity,
			NucleiIDs:       splitCSV(scanOpts.nucleiIDs),
			POCConcurrency:  scanOpts.pocConcurrency,
			HTTPConcurrency: scanOpts.httpConcurrency,
			HTTPTimeoutSec:  scanOpts.httpTimeout,
			Engines:         scanOpts.engines,
			TemplateDir:     templateDir,
			TempDir:         scanOpts.tempDir,
			LogFormat:       logFormat,
			RawArgs:         os.Args[1:],
			AcceptedCompatFlags: map[string]any{
				"dbs": scanOpts.dbs, "risk": scanOpts.risk, "deep-scan": scanOpts.deepScan,
				"nocrack": scanOpts.noCrack, "noimg": scanOpts.noImg, "random": scanOpts.random,
				"rdp": scanOpts.rdp, "spy-only": scanOpts.spyOnly, "xray-poc-name": scanOpts.xrayPOCName,
			},
		}

		emitter := event.NewEmitter(os.Stdout)
		runner := scan.NewRunner(cfg, os.Stdout, emitter)
		result, scanErr := runner.Run(ctx)
		if result == nil {
			return scanErr
		}

		paths, err := report.WriteAll(result, wd)
		if err != nil {
			runner.Logf("[ERR] Could not write reports: %v", err)
			if scanErr != nil {
				return fmt.Errorf("%w; report error: %v", scanErr, err)
			}
			return err
		}
		runner.EmitReportWritten(paths)

		if scanErr != nil {
			return scanErr
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOpts.targetURL, "url", "u", "", "single URL target")
	scanCmd.Flags().StringVarP(&scanOpts.targetIP, "ip", "i", "", "single IP, host, CIDR, or comma-separated host targets")
	scanCmd.Flags().StringVar(&scanOpts.urlFile, "urlfile", "", "file containing URL targets")
	scanCmd.Flags().StringVar(&scanOpts.ipFile, "ipfile", "", "file containing IP or host targets")
	scanCmd.Flags().StringVarP(&scanOpts.cyber, "cyber", "c", "", "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().StringVar(&scanOpts.spy, "spy", "", "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().StringVarP(&scanOpts.ports, "ports", "p", "TOP100", "ports, ranges, or presets TOP100/TOP500")
	scanCmd.Flags().StringVarP(&scanOpts.proxy, "proxy", "x", "", "HTTP/SOCKS proxy URL")
	scanCmd.Flags().StringVar(&scanOpts.outName, "outname", "SpringX", "report display name compatibility option")
	scanCmd.Flags().BoolVar(&scanOpts.web, "web", false, "run in WebUI-compatible mode")
	scanCmd.Flags().BoolVar(&scanOpts.noBrowser, "no-browser", false, "do not open a browser")
	scanCmd.Flags().BoolVar(&scanOpts.dbs, "dbs", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.risk, "risk", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.deepScan, "deep-scan", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.noPing, "noping", false, "skip ICMP ping compatibility option")
	scanCmd.Flags().BoolVar(&scanOpts.noPOC, "nopoc", false, "disable POC scanning")
	scanCmd.Flags().BoolVar(&scanOpts.noCrack, "nocrack", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.noImg, "noimg", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.random, "random", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.rdp, "rdp", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().BoolVar(&scanOpts.spyOnly, "spy-only", false, "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().IntVarP(&scanOpts.threads, "threads", "t", 5, "logical worker count")
	scanCmd.Flags().IntVar(&scanOpts.doneMinutes, "done", 10, "maximum scan duration in minutes")
	scanCmd.Flags().StringVar(&scanOpts.chanRatio, "chan", "0.8", "legacy dynamic concurrency ratio")
	scanCmd.Flags().StringVar(&scanOpts.platform, "platform", "", "compatibility platform filter")
	scanCmd.Flags().IntVar(&scanOpts.size, "size", 100, "maximum expanded targets from files/CIDR")
	scanCmd.Flags().IntVar(&scanOpts.gonmapTimeout, "gonmap-timeout", 5, "TCP connect timeout in seconds")
	scanCmd.Flags().StringVar(&scanOpts.nucleiTags, "nuclei-tags", "", "comma-separated nuclei tags")
	scanCmd.Flags().StringVar(&scanOpts.nucleiSeverity, "nuclei-severity", "", "comma-separated nuclei severities")
	scanCmd.Flags().StringVar(&scanOpts.nucleiIDs, "nuclei-ids", "", "comma-separated nuclei template IDs")
	scanCmd.Flags().StringVar(&scanOpts.nucleiTemplateDir, "nuclei-template-dir", "", "override nuclei template directory")
	scanCmd.Flags().StringVar(&scanOpts.xrayPOCName, "xray-poc-name", "", "compatibility flag, accepted but not implemented in MVP")
	scanCmd.Flags().IntVar(&scanOpts.pocConcurrency, "poc-concurrency", 5, "POC scanning concurrency")
	scanCmd.Flags().IntVar(&scanOpts.httpConcurrency, "http-concurrency", 10, "HTTP probe concurrency")
	scanCmd.Flags().IntVar(&scanOpts.httpTimeout, "http-timeout", 10, "HTTP request timeout in seconds")
	scanCmd.Flags().StringVar(&scanOpts.engines, "engines", "", "compatibility engine selector")
	scanCmd.Flags().StringVar(&scanOpts.logFormat, "log-format", "mixed", "output log format: mixed or jsonl")
	scanCmd.Flags().BoolVar(&scanOpts.jsonlOnly, "jsonl-only", false, "shortcut for --log-format jsonl")
	scanCmd.Flags().StringVar(&scanOpts.tempDir, "temp-dir", "", "temporary directory for Nuclei (default: SPRINGX_TEMP_DIR or D:\\Temp on Windows)")
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func printBanner() {
	fmt.Println(`  ____             _             __  __`)
	fmt.Println(` / ___| _ __  _ __(_)_ __   __ _\ \/ /`)
	fmt.Println(` \___ \| '_ \| '__| | '_ \ / _  |>  < `)
	fmt.Println(`  ___) | |_) | |  | | | | | (_| /_/\_\`)
	fmt.Println(` |____/| .__/|_|  |_|_| |_|\__, |`)
	fmt.Println(`       |_|                 |___/`)
	fmt.Println(` SpringX Scanner`)
	fmt.Println()
}

func printDisclaimer() {
	fmt.Println("免责声明:           本软件仅用于经授权的安全测试，禁止使用本工具实施未授权测试。若违法使用导致任何法律责任，均由使用者自行承担，与软件作者无关。")
	fmt.Println()
}

func normalizedLogFormat(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "mixed"
	}
	return value
}
