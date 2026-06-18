package nuclei

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	Concurrency int
	Timeout     int
	Proxy       string
	TempDir     string
	Logger      func(string, ...any)
	OnFinding   func(model.Vulnerability)
}

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
		lib.WithTemplateFilters(lib.TemplateFilters{Tags: cfg.Tags, Severity: cfg.Severity}),
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

	engine, err := lib.NewNucleiEngineCtx(ctx, options...)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	engine.LoadTargets(cfg.Targets, false)
	var vulns []model.Vulnerability
	err = engine.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		vuln := convertEvent(ev)
		vulns = append(vulns, vuln)
		if cfg.OnFinding != nil {
			cfg.OnFinding(vuln)
		}
	})
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
	if ev.Info.Classification != nil {
		metadata["classification"] = ev.Info.Classification
	}
	if len(metadata) == 0 {
		metadata = nil
	}

	return model.Vulnerability{
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
	}
}

func compact(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 512 {
		return value[:512] + "..."
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
	return fmt.Sprintf("targets=%d templates=%s severity=%s tags=%s", len(c.Targets), c.TemplateDir, c.Severity, strings.Join(c.Tags, ","))
}
