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

	for _, rawURL := range targets.URLs {
		select {
		case <-ctx.Done():
			return r.finish(result, "stopped", ctx.Err())
		default:
		}
		r.emitter.Emit("target_discovered", map[string]any{"url": rawURL})
		svc := ProbeURL(ctx, rawURL, r.cfg.Timeout(), r.cfg.Proxy)
		result.Targets = append(result.Targets, svc)
		if svc.StatusCode > 0 {
			r.Logf("[INF] [HTTP] %s [%d] %s", svc.URL, svc.StatusCode, svc.Title)
			r.emitter.Emit("service_detected", serviceEvent(svc))
		} else if svc.Error != "" {
			r.Logf("[WRN] [HTTP] %s %s", rawURL, svc.Error)
		}
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
	if r.cfg.NoPOC {
		result.Scan.POCSkipped = true
		result.Scan.POCSkipReason = "--nopoc enabled"
		r.Logf("[INF] POC scan skipped: --nopoc enabled")
		return nil
	}
	if !dirHasTemplates(r.cfg.TemplateDir) {
		result.Scan.POCSkipped = true
		result.Scan.POCSkipReason = "nuclei template directory not found or empty: " + r.cfg.TemplateDir
		r.Logf("[WRN] POC scan skipped: %s", result.Scan.POCSkipReason)
		return nil
	}

	targets := nucleiTargets(result.Targets)
	if len(targets) == 0 {
		result.Scan.POCSkipped = true
		result.Scan.POCSkipReason = "no HTTP targets for POC scanning"
		r.Logf("[INF] POC scan skipped: no HTTP targets")
		return nil
	}

	result.Scan.POCExecuted = true
	r.Logf("[INF] 开始 Nuclei POC 扫描，目标:%d 模板:%s", len(targets), r.cfg.TemplateDir)
	r.emitter.Emit("poc_started", map[string]any{"engine": "nuclei", "targets": len(targets)})

	vulns, err := nucleirunner.Run(ctx, nucleirunner.Config{
		Targets:     targets,
		TemplateDir: r.cfg.TemplateDir,
		Tags:        r.cfg.NucleiTags,
		Severity:    r.cfg.NucleiSeverity,
		Concurrency: r.cfg.PocConcurrency(),
		Timeout:     int(r.cfg.Timeout().Seconds()),
		Proxy:       r.cfg.Proxy,
		TempDir:     r.cfg.TempDir,
		Logger:      r.Logf,
		OnFinding: func(v model.Vulnerability) {
			r.Logf("[INF] [NucleiPOC] %s - [%s] %s", v.Target, severityLabel(v.Severity), v.TemplateID)
			r.emitter.Emit("vulnerability_found", map[string]any{"engine": v.Engine, "template_id": v.TemplateID, "severity": v.Severity, "target": v.Target})
		},
	})
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	r.Logf("[INF] Nuclei POC 扫描完成，发现 %d 个结果", len(vulns))
	return err
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

func (r *Runner) Logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.logs = append(r.logs, line)
	r.mu.Unlock()
	fmt.Fprintln(r.out, line)
}

func (r *Runner) note(result *model.Result, msg string) {
	result.Notes = append(result.Notes, msg)
	r.Logf("[WRN] %s", msg)
}

func dirHasTemplates(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func nucleiTargets(services []model.Service) []string {
	var targets []string
	for _, svc := range services {
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
	return map[string]any{
		"host": svc.Host, "ip": svc.IP, "port": svc.Port, "protocol": svc.Protocol,
		"scheme": svc.Scheme, "url": svc.URL, "status_code": svc.StatusCode,
		"title": svc.Title, "server": svc.Server, "tls": svc.TLS,
	}
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
