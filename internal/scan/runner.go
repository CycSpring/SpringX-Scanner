package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/model"
	nucleirunner "github.com/CycSpring/SpringX-Scanner/internal/poc/nuclei"
)

type Runner struct {
	cfg     Config
	out     io.Writer
	emitter *event.Emitter
	mu      sync.Mutex
	logs    []string
}

func NewRunner(cfg Config, out io.Writer, emitter *event.Emitter) *Runner {
	return &Runner{cfg: cfg, out: out, emitter: emitter}
}

func (r *Runner) Run(ctx context.Context) (*model.Result, error) {
	start := time.Now()
	result := &model.Result{
		Scan: model.ScanInfo{
			ID:        fmt.Sprintf("%x", start.UnixNano()),
			Version:   r.cfg.Version,
			Status:    "running",
			StartedAt: start,
			Args:      append([]string{}, r.cfg.RawArgs...),
		},
		Parameters: r.cfg.Parameters(),
	}
	r.emitter.SetScanID(result.Scan.ID)

	r.Logf(">>> Start scan task")
	r.Logf("[INF] SpringX self-owned scanner core %s", r.cfg.Version)
	r.emitter.Emit("scan_started", map[string]any{"id": result.Scan.ID, "args": r.cfg.RawArgs})

	if r.cfg.Cyber != "" || r.cfg.Spy != "" {
		r.note(result, "FOFA/Hunter/Spy discovery is not implemented in MVP; direct targets will still be scanned.")
	}

	ports, err := ParsePorts(r.cfg.Ports)
	if err != nil {
		return r.finish(result, "failed", err)
	}
	targets, err := ResolveTargets(r.cfg)
	if err != nil {
		return r.finish(result, "failed", err)
	}
	r.Logf("[INF] 目标URL:%d 主机:%d 端口:%d 并发:%d", len(targets.URLs), len(targets.Hosts), len(ports), r.cfg.PortConcurrency())

	if maxDuration := r.cfg.MaxDuration(); maxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxDuration)
		defer cancel()
	}

	// Announce all URL targets up front so the WebUI sees them immediately
	// (target_discovered is a discovery signal, not a probe-completion signal).
	for _, rawURL := range targets.URLs {
		r.emitter.Emit("target_discovered", map[string]any{"url": rawURL})
	}
	// Probe URLs concurrently with a shared keep-alive client. A failed probe
	// still emits service_detected (status_code=0 + error) so failures are
	// visible in real time rather than only in the log.
	if len(targets.URLs) > 0 {
		client := sharedHTTPClient(r.cfg.HTTPTimeout(), r.cfg.Proxy, r.cfg.HttpConcurrency())
		services := probeURLs(ctx, targets.URLs, r.cfg.HttpConcurrency(), client, func(svc model.Service) {
			if svc.StatusCode > 0 {
				r.Logf("[INF] [HTTP] %s [%d] %s", svc.URL, svc.StatusCode, svc.Title)
			} else if svc.Error != "" {
				r.Logf("[WRN] [HTTP] %s %s", svc.URL, svc.Error)
			}
			if svc.StatusCode > 0 || svc.Error != "" {
				r.emitter.Emit("service_detected", serviceEvent(svc))
			}
		})
		result.Targets = append(result.Targets, services...)
	}

	if len(targets.Hosts) > 0 {
		total := len(targets.Hosts) * len(ports)
		r.Logf("[INF] 开始扫描端口:%d 主机:%d 任务总数:%d 端口连接超时:%s", len(ports), len(targets.Hosts), total, r.cfg.Timeout())
		services := ScanPorts(ctx, targets.Hosts, ports, r.cfg.PortConcurrency(), r.cfg.Timeout(), r.cfg.Proxy, func(svc model.Service) {
			r.Logf("[INF] [Port] %s:%d %s %s", svc.Host, svc.Port, svc.Protocol, svc.Title)
			r.emitter.Emit("port_open", serviceEvent(svc))
		})
		result.Targets = append(result.Targets, services...)
	}

	result.Targets = dedupeServices(result.Targets)
	r.Logf("[INF] 存活服务:%d", len(result.Targets))

	if err := r.runPOC(ctx, result); err != nil {
		result.Scan.Errors = append(result.Scan.Errors, err.Error())
		r.Logf("[ERR] POC scan error: %v", err)
	}

	if ctx.Err() != nil {
		return r.finish(result, "stopped", ctx.Err())
	}
	return r.finish(result, "completed", nil)
}

func (r *Runner) runPOC(ctx context.Context, result *model.Result) error {
	templateDir := r.cfg.TemplateDir
	// --use-builtin-smoke-template: write the embedded smoke template into a
	// temp dir and use it. This is a testing affordance, never a silent default.
	if r.cfg.UseBuiltinSmoke {
		dir, err := writeBuiltinSmokeTemplate(r.cfg.GetTempDir())
		if err != nil {
			result.Scan.POC = model.POCInfo{
				Engine:      "nuclei",
				TemplateDir: templateDir,
				Tags:        append([]string{}, r.cfg.NucleiTags...),
				Severity:    r.cfg.NucleiSeverity,
				IDs:         append([]string{}, r.cfg.NucleiIDs...),
				Error:       "failed to write built-in smoke template: " + err.Error(),
			}
			r.markPOCSkipped(result, result.Scan.POC.Error)
			r.Logf("[WRN] POC scan skipped: %s", result.Scan.POCSkipReason)
			r.emitPOCCompleted(result)
			return nil
		}
		templateDir = dir
	}
	tplCount, tplVersion := countTemplates(templateDir)
	result.Scan.POC = model.POCInfo{
		Engine:          "nuclei",
		TemplateDir:     templateDir,
		TemplateCount:   tplCount,
		TemplateVersion: tplVersion,
		Tags:            append([]string{}, r.cfg.NucleiTags...),
		Severity:        r.cfg.NucleiSeverity,
		IDs:             append([]string{}, r.cfg.NucleiIDs...),
	}
	if r.cfg.NoPOC {
		r.markPOCSkipped(result, "--nopoc enabled")
		r.Logf("[INF] POC scan skipped: --nopoc enabled")
		r.emitPOCCompleted(result)
		return nil
	}
	if !dirHasTemplates(templateDir) {
		r.markPOCSkipped(result, "nuclei template directory not found or empty: "+templateDir+" (use --nuclei-template-dir to specify, or --use-builtin-smoke-template for testing)")
		r.Logf("[WRN] POC scan skipped: %s", result.Scan.POCSkipReason)
		r.emitPOCCompleted(result)
		return nil
	}

	targets := nucleiTargets(result.Targets)
	if len(targets) == 0 {
		r.markPOCSkipped(result, "no HTTP targets for POC scanning")
		r.Logf("[INF] POC scan skipped: no HTTP targets")
		r.emitPOCCompleted(result)
		return nil
	}

	start := time.Now()
	result.Scan.POCExecuted = true
	result.Scan.POC.Executed = true
	result.Scan.POC.Targets = len(targets)
	r.Logf("[INF] 开始 Nuclei POC 扫描，目标:%d 模板:%s tags:%s severity:%s ids:%s", len(targets), templateDir, strings.Join(r.cfg.NucleiTags, ","), r.cfg.NucleiSeverity, strings.Join(r.cfg.NucleiIDs, ","))
	r.emitter.Emit("poc_started", map[string]any{
		"engine": "nuclei", "targets": len(targets), "template_dir": templateDir,
		"template_count": tplCount, "template_version": tplVersion,
		"tags": r.cfg.NucleiTags, "severity": r.cfg.NucleiSeverity, "ids": r.cfg.NucleiIDs,
	})

	vulns, err := nucleirunner.Run(ctx, nucleirunner.Config{
		Targets:     targets,
		TemplateDir: templateDir,
		Tags:        r.cfg.NucleiTags,
		Severity:    r.cfg.NucleiSeverity,
		IDs:         r.cfg.NucleiIDs,
		Concurrency: r.cfg.PocConcurrency(),
		Timeout:     int(r.cfg.Timeout().Seconds()),
		Proxy:       r.cfg.Proxy,
		TempDir:     r.cfg.GetTempDir(),
		Logger:      r.Logf,
		OnFinding: func(v model.Vulnerability) {
			r.Logf("[INF] [NucleiPOC] %s - [%s] %s", v.Target, severityLabel(v.Severity), v.TemplateID)
			r.emitter.Emit("vulnerability_found", vulnEvent(v))
		},
		OnProgress: func(s nucleirunner.ProgressStats) {
			percent := 0
			if s.Total > 0 {
				pct := int(float64(s.Done) / float64(s.Total) * 100)
				if pct > 100 {
					pct = 100
				}
				percent = pct
			}
			r.emitter.Emit("poc_progress", map[string]any{
				"engine":         "nuclei",
				"done":           s.Done,
				"total":          s.Total,
				"percent":        percent,
				"rules":          s.Rules,
				"findings":       s.Found,
				"errors":         s.Errors,
				"template_count": tplCount,
				"targets":        len(targets),
			})
		},
	})
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	result.Scan.POC.Findings = len(vulns)
	result.Scan.POC.Duration = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		result.Scan.POC.Error = err.Error()
	}
	r.Logf("[INF] Nuclei POC 扫描完成，发现 %d 个结果，耗时:%s", len(vulns), result.Scan.POC.Duration)
	r.emitPOCCompleted(result)
	return err
}

func (r *Runner) markPOCSkipped(result *model.Result, reason string) {
	result.Scan.POCSkipped = true
	result.Scan.POCSkipReason = reason
	result.Scan.POC.Skipped = true
	result.Scan.POC.SkipReason = reason
}

func (r *Runner) emitPOCCompleted(result *model.Result) {
	r.emitter.Emit("poc_completed", map[string]any{
		"engine": result.Scan.POC.Engine, "targets": result.Scan.POC.Targets,
		"findings": result.Scan.POC.Findings, "duration": result.Scan.POC.Duration,
		"template_dir":     result.Scan.POC.TemplateDir,
		"template_count":   result.Scan.POC.TemplateCount,
		"template_version": result.Scan.POC.TemplateVersion,
		"skipped":          result.Scan.POC.Skipped,
		"skip_reason":      result.Scan.POC.SkipReason, "error": result.Scan.POC.Error,
	})
}

func (r *Runner) finish(result *model.Result, status string, err error) (*model.Result, error) {
	result.Scan.Status = status
	result.Scan.FinishedAt = time.Now()
	result.Scan.Duration = result.Scan.FinishedAt.Sub(result.Scan.StartedAt).Round(time.Millisecond).String()
	if err != nil && status == "failed" {
		result.Scan.Errors = append(result.Scan.Errors, err.Error())
		r.emitter.EmitError("scan_failed", err, map[string]any{"id": result.Scan.ID})
	} else {
		r.emitter.Emit("scan_completed", map[string]any{"id": result.Scan.ID, "status": status})
	}
	result.Logs = append([]string{}, r.logs...)
	if err != nil && status == "failed" {
		return result, err
	}
	return result, nil
}

func (r *Runner) EmitReportWritten(paths model.ReportPaths) {
	r.emitter.Emit("report_written", map[string]any{
		"html": paths.HTML, "markdown": paths.Markdown, "json": paths.JSON,
	})
}

func (r *Runner) Logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.logs = append(r.logs, line)
	r.mu.Unlock()
	if r.cfg.JSONLOnly() {
		r.emitter.Emit("log", map[string]any{"message": line})
		return
	}
	fmt.Fprintln(r.out, line)
}

func (r *Runner) note(result *model.Result, msg string) {
	result.Notes = append(result.Notes, msg)
	r.Logf("[WRN] %s", msg)
}

// countTemplates walks dir and returns (count, version): the number of
// .yaml/.yml/.json files and the contents of a VERSION file if present. It is
// called once per scan in the POC phase, so the walk cost is acceptable even
// for large template directories.
func countTemplates(dir string) (int, string) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return 0, ""
	}
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			count++
		}
		return nil
	})
	version := ""
	if data, err := os.ReadFile(filepath.Join(dir, "VERSION")); err == nil {
		version = strings.TrimSpace(string(data))
	}
	return count, version
}

func dirHasTemplates(dir string) bool {
	count, _ := countTemplates(dir)
	return count > 0
}

func nucleiTargets(services []model.Service) []string {
	var targets []string
	for _, svc := range services {
		// Skip failed probes so nuclei does not waste time re-attempting URLs
		// that already failed HTTP detection. A successful probe has a status
		// code and no error.
		if svc.Error != "" || svc.StatusCode <= 0 {
			continue
		}
		if svc.URL != "" {
			targets = appendUnique(targets, svc.URL)
			continue
		}
		if svc.Scheme != "" && svc.Host != "" && svc.Port > 0 {
			url := fmt.Sprintf("%s://%s:%d/", svc.Scheme, svc.Host, svc.Port)
			if defaultPort(svc.Scheme, svc.Port) {
				url = fmt.Sprintf("%s://%s/", svc.Scheme, svc.Host)
			}
			targets = appendUnique(targets, url)
		}
	}
	return targets
}

func dedupeServices(services []model.Service) []model.Service {
	seen := map[string]struct{}{}
	var out []model.Service
	for _, svc := range services {
		key := fmt.Sprintf("%s|%d|%s|%s", strings.ToLower(svc.Host), svc.Port, svc.Scheme, svc.URL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, svc)
	}
	return out
}

func serviceEvent(svc model.Service) map[string]any {
	ev := map[string]any{
		"host": svc.Host, "ip": svc.IP, "port": svc.Port, "protocol": svc.Protocol,
		"scheme": svc.Scheme, "url": svc.URL, "status_code": svc.StatusCode,
		"title": svc.Title, "server": svc.Server, "tls": svc.TLS,
		"content_type": svc.ContentType, "content_length": svc.ContentLength,
		"location": svc.Location, "favicon_hash": svc.FaviconHash,
		"technologies": svc.Technologies, "fingerprint_sources": svc.FingerprintSources,
		"service": svc.Service,
	}
	// Carry the probe error so failed service_detected events are self-describing
	// (status_code=0 + error) for the WebUI; omitted on success.
	if svc.Error != "" {
		ev["error"] = svc.Error
	}
	// Carry the TCP banner (e.g. SSH/FTP greeting) for non-HTTP open ports.
	if svc.Banner != "" {
		ev["banner"] = svc.Banner
	}
	return ev
}

// vulnEvent builds the vulnerability_found event payload from a model
// Vulnerability. It carries the full field set so the WebUI can render a
// detail expansion (matched_at, description, request/response summaries, etc.)
// in real time without waiting for the final report JSON. Empty string fields
// are omitted to keep the live stream compact.
func vulnEvent(v model.Vulnerability) map[string]any {
	out := map[string]any{
		"engine":      v.Engine,
		"template_id": v.TemplateID,
		"severity":    v.Severity,
		"target":      v.Target,
		"name":        v.Name,
	}
	if v.MatchedAt != "" {
		out["matched_at"] = v.MatchedAt
	}
	if v.Type != "" {
		out["type"] = v.Type
	}
	if v.Description != "" {
		out["description"] = v.Description
	}
	if v.MatcherName != "" {
		out["matcher_name"] = v.MatcherName
	}
	if v.ExtractorName != "" {
		out["extractor_name"] = v.ExtractorName
	}
	if len(v.ExtractedResults) > 0 {
		out["extracted_results"] = v.ExtractedResults
	}
	if v.RequestSummary != "" {
		out["request_summary"] = v.RequestSummary
	}
	if v.ResponseSummary != "" {
		out["response_summary"] = v.ResponseSummary
	}
	if !v.Timestamp.IsZero() {
		out["timestamp"] = v.Timestamp
	}
	return out
}

func severityLabel(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return value
	}
}
