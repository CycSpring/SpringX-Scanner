package nuclei

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
	lib "github.com/projectdiscovery/nuclei/v3/lib"
	pdconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type Config struct {
	Targets     []string
	TemplateDir string
	Tags        []string
	Severity    string
	IDs         []string
	Concurrency int
	Timeout     int
	Proxy       string
	TempDir     string
	Logger      func(string, ...any)
	OnFinding   func(model.Vulnerability)
	// OnProgress, if set, is invoked periodically while nuclei runs with the
	// real request counters driven by nuclei's own progress hooks: done
	// requests, total requests, matched findings, and the rules (template)
	// count reported at Init.
	OnProgress func(stats ProgressStats)
}

// ProgressStats is the snapshot passed to OnProgress. Done/Total are request
// counters; Total may grow during a scan (AddToTotal), so percent is clamped
// to [0,100]. Rules is the number of templates nuclei loaded for this run.
type ProgressStats struct {
	Done   int64
	Total  int64
	Rules  int
	Found  int64
	Errors int64
}

// progressInterval is how often OnProgress fires during a scan.
const progressInterval = 3 * time.Second

func Run(ctx context.Context, cfg Config) ([]model.Vulnerability, error) {
	if len(cfg.Targets) == 0 {
		return nil, nil
	}
	if cfg.TemplateDir == "" {
		return nil, errors.New("nuclei template directory is empty")
	}
	if err := prepareNucleiConfig(cfg); err != nil {
		return nil, err
	}

	options := []lib.NucleiSDKOptions{
		lib.DisableUpdateCheck(),
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{Templates: []string{cfg.TemplateDir}}),
		lib.WithTemplateFilters(lib.TemplateFilters{Tags: cfg.Tags, Severity: cfg.Severity, IDs: cfg.IDs}),
		lib.WithConcurrency(lib.Concurrency{
			TemplateConcurrency:           max(1, cfg.Concurrency),
			HostConcurrency:               max(1, cfg.Concurrency),
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    max(1, cfg.Concurrency),
			ProbeConcurrency:              max(1, cfg.Concurrency),
		}),
		lib.WithNetworkConfig(lib.NetworkConfig{Timeout: max(1, cfg.Timeout), Retries: 1, LeaveDefaultPorts: true}),
		lib.WithVerbosity(lib.VerbosityOptions{Silent: true}),
	}
	if cfg.Proxy != "" {
		options = append(options, lib.WithProxy([]string{cfg.Proxy}, true))
	}
	if cfg.TempDir != "" {
		_ = os.MkdirAll(cfg.TempDir, 0755)
		options = append(options, lib.WithTemporaryDirectory(cfg.TempDir))
	}
	// Inject a custom progress writer so nuclei reports real request counters
	// (Init total + per-request increments) back to the caller. This drives the
	// deterministic POC progress bar instead of a wall-clock guess.
	var prog *pocProgress
	if cfg.OnProgress != nil {
		prog = newPocProgress(cfg.OnProgress, progressInterval)
		options = append(options, lib.UseStatsWriter(prog))
	}

	engine, err := lib.NewNucleiEngineCtx(ctx, options...)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	engine.LoadTargets(cfg.Targets, false)
	var (
		vulns  []model.Vulnerability
		vulnMu sync.Mutex
	)
	err = engine.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		vuln := convertEvent(ev)
		vulnMu.Lock()
		vulns = append(vulns, vuln)
		vulnMu.Unlock()
		if cfg.OnFinding != nil {
			cfg.OnFinding(vuln)
		}
	})
	// Stop the progress ticker; Stop emits a final snapshot with the terminal
	// counters so the caller's last update reflects the real totals.
	if prog != nil {
		prog.Stop()
	}
	if err != nil {
		return vulns, err
	}
	return vulns, nil
}

func prepareNucleiConfig(cfg Config) error {
	configDir := filepath.Join(firstNonEmpty(cfg.TempDir, os.TempDir()), "springx-nuclei-config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}
	pdconfig.DefaultConfig.SetConfigDir(configDir)
	pdconfig.DefaultConfig.SetTemplatesDir(cfg.TemplateDir)
	pdconfig.DefaultConfig.DisableUpdateCheck()

	ignorePath := pdconfig.DefaultConfig.GetIgnoreFilePath()
	ignoreContent := []byte("tags: []\nfiles: []\n")
	if err := os.WriteFile(ignorePath, ignoreContent, 0644); err != nil {
		return err
	}
	if err := pdconfig.DefaultConfig.UpdateNucleiIgnoreHash(); err != nil && cfg.Logger != nil {
		cfg.Logger("[WRN] Could not update nuclei ignore hash: %v", err)
	}
	return nil
}

func convertEvent(ev *output.ResultEvent) model.Vulnerability {
	if ev == nil {
		return model.Vulnerability{}
	}
	name := ev.Info.Name
	if name == "" {
		name = ev.TemplateID
	}
	target := ev.Matched
	if target == "" {
		target = ev.URL
	}
	if target == "" {
		target = ev.Host
	}
	severity := ev.Info.SeverityHolder.Severity.String()
	if severity == "" {
		severity = "unknown"
	}
	timestamp := ev.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	metadata := map[string]any{}
	for k, v := range ev.Metadata {
		metadata[k] = v
	}
	if len(metadata) == 0 {
		metadata = nil
	}

	v := model.Vulnerability{
		Engine:           "nuclei",
		TemplateID:       ev.TemplateID,
		Name:             name,
		Severity:         severity,
		Target:           target,
		MatchedAt:        ev.Matched,
		MatcherName:      ev.MatcherName,
		ExtractorName:    ev.ExtractorName,
		Type:             ev.Type,
		Description:      ev.Info.Description,
		ExtractedResults: ev.ExtractedResults,
		RequestSummary:   compact(ev.Request),
		ResponseSummary:  compact(ev.Response),
		Timestamp:        timestamp,
		Metadata:         metadata,
		Tags:             ev.Info.Tags.ToSlice(),
		Remediation:      ev.Info.Remediation,
		Impact:           ev.Info.Impact,
		CURLCommand:      ev.CURLCommand,
	}
	// Reference is a pointer; nil-check before dereferencing.
	if ev.Info.Reference != nil {
		v.References = ev.Info.Reference.ToSlice()
	}
	// Classification is a pointer; extract structured CVE/CWE/CVSS fields.
	if ev.Info.Classification != nil {
		c := ev.Info.Classification
		v.CVE = c.CVEID.ToSlice()
		v.CWE = c.CWEID.ToSlice()
		v.CVSSMetrics = c.CVSSMetrics
		v.CVSSScore = c.CVSSScore
		v.CPE = c.CPE
	}
	return v
}

// compact normalizes whitespace in request/response evidence while preserving
// line breaks so the report can render HTTP messages in a readable format.
// Trailing spaces per line are trimmed and the total is capped at 2048 chars.
func compact(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	value = strings.Join(lines, "\n")
	if len(value) > 2048 {
		return value[:2048] + "\n..."
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (c Config) String() string {
	return fmt.Sprintf("targets=%d templates=%s severity=%s tags=%s ids=%s", len(c.Targets), c.TemplateDir, c.Severity, strings.Join(c.Tags, ","), strings.Join(c.IDs, ","))
}
