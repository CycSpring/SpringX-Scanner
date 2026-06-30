package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/model"
	"github.com/CycSpring/SpringX-Scanner/internal/report"
)

func TestRunnerNucleiSmokeReportConsistency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/springx-smoke" {
			_, _ = w.Write([]byte("springx-smoke-ok"))
			return
		}
		_, _ = w.Write([]byte("<html><title>SpringX Smoke</title></html>"))
	}))
	defer server.Close()

	workDir := t.TempDir()
	cfg := Config{
		Version:       "test",
		WorkDir:       workDir,
		TargetURL:     server.URL,
		Ports:         "80,443",
		TemplateDir:   filepath.Join("..", "..", "testdata", "nuclei"),
		TempDir:       t.TempDir(),
		NucleiIDs:     []string{"springx-smoke"},
		GonmapTimeout: 2,
		RawArgs:       []string{"scan", "-u", server.URL},
	}
	result, err := NewRunner(cfg, os.Stdout, event.NewEmitter(io.Discard)).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := len(result.Vulnerabilities); got != 1 {
		t.Fatalf("vulnerabilities = %d, want 1: %+v", got, result.Vulnerabilities)
	}
	if result.Scan.POC.Findings != 1 || !result.Scan.POC.Executed || result.Scan.POC.Skipped {
		t.Fatalf("unexpected POC info: %+v", result.Scan.POC)
	}
	paths, err := report.WriteAll(result, workDir)
	if err != nil {
		t.Fatalf("WriteAll returned error: %v", err)
	}

	var jsonResult struct {
		Vulnerabilities []any `json:"vulnerabilities"`
	}
	data, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &jsonResult); err != nil {
		t.Fatal(err)
	}
	if len(jsonResult.Vulnerabilities) != 1 {
		t.Fatalf("json vulnerabilities = %d", len(jsonResult.Vulnerabilities))
	}

	md, err := os.ReadFile(paths.Markdown)
	if err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(paths.HTML)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"markdown": string(md), "html": string(html)} {
		if !strings.Contains(body, "springx-smoke") {
			t.Fatalf("%s report missing springx-smoke", name)
		}
	}
}

func TestRunnerMissingTemplateDirStillReportsSkippedPOC(t *testing.T) {
	workDir := t.TempDir()
	cfg := Config{
		Version:       "test",
		WorkDir:       workDir,
		TargetURL:     "http://127.0.0.1/",
		Ports:         "80",
		TemplateDir:   filepath.Join(workDir, "missing"),
		TempDir:       t.TempDir(),
		GonmapTimeout: 1,
	}
	result, err := NewRunner(cfg, os.Stdout, event.NewEmitter(io.Discard)).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !result.Scan.POCSkipped || !result.Scan.POC.Skipped {
		t.Fatalf("expected skipped POC info: %+v", result.Scan.POC)
	}
	if result.Scan.POCSkipReason == "" || !strings.Contains(result.Scan.POCSkipReason, "template directory") {
		t.Fatalf("unexpected skip reason: %q", result.Scan.POCSkipReason)
	}
	if _, err := report.WriteAll(result, workDir); err != nil {
		t.Fatalf("WriteAll returned error: %v", err)
	}
}

func TestRunnerJSONLOnlyEmitsLogsAsEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>JSONL Smoke</title></html>"))
	}))
	defer server.Close()

	var buf bytes.Buffer
	emitter := event.NewEmitter(&buf)
	cfg := Config{
		Version:       "test",
		TargetURL:     server.URL,
		Ports:         "80",
		NoPOC:         true,
		GonmapTimeout: 1,
		LogFormat:     "jsonl",
	}
	result, err := NewRunner(cfg, &buf, emitter).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Logs) == 0 {
		t.Fatal("expected human logs to still be stored in result")
	}

	scanner := bufio.NewScanner(&buf)
	var sawLog bool
	var previousSeq uint64
	for scanner.Scan() {
		var ev event.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("expected JSONL-only output, got %q: %v", scanner.Text(), err)
		}
		if ev.Version != event.ProtocolVersion {
			t.Fatalf("unexpected event version: %q", ev.Version)
		}
		if ev.ScanID != result.Scan.ID {
			t.Fatalf("event scan_id = %q, want %q", ev.ScanID, result.Scan.ID)
		}
		if ev.Seq <= previousSeq {
			t.Fatalf("event seq did not increase: previous=%d current=%d", previousSeq, ev.Seq)
		}
		previousSeq = ev.Seq
		if ev.Type == "log" {
			sawLog = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan output: %v", err)
	}
	if !sawLog {
		t.Fatal("expected at least one log event")
	}
}

// TestRunnerConcurrentURLProbes verifies the HTTP probe worker pool: two URL
// targets are probed concurrently, both produce service_detected events, the
// result contains both services, and event seqs are strictly monotonic and
// unique (codex防坑点4). Event ORDER is not asserted (concurrency is allowed
// to reorder completion — codex防坑点8).
func TestRunnerConcurrentURLProbes(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>srv1</title>"))
	}))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>srv2</title>"))
	}))
	defer srv1.Close()
	defer srv2.Close()

	var buf bytes.Buffer
	emitter := event.NewEmitter(&buf)
	cfg := Config{
		Version:         "test",
		WorkDir:         t.TempDir(),
		TargetURL:       srv1.URL + "," + srv2.URL, // ResolveTargets splits comma list? No — TargetURL is single. Use URLFile instead.
		GonmapTimeout:   2,
		HTTPTimeoutSec:  5,
		HTTPConcurrency: 2,
		NoPOC:           true,
		RawArgs:         []string{"scan"},
	}
	// TargetURL is single; put both in a urlfile so both get probed.
	urlFile := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(urlFile, []byte(srv1.URL+"\n"+srv2.URL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.URLFile = urlFile
	cfg.TargetURL = ""

	result, err := NewRunner(cfg, &buf, emitter).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Targets) != 2 {
		t.Fatalf("result.Targets = %d, want 2", len(result.Targets))
	}

	// Decode events; assert seq strictly increasing + unique, and 2 service_detected.
	events := decodeScanEvents(t, &buf)
	seen := map[uint64]bool{}
	var detected int
	var prevSeq uint64
	for _, ev := range events {
		if seen[ev.Seq] {
			t.Fatalf("duplicate seq %d", ev.Seq)
		}
		seen[ev.Seq] = true
		if ev.Seq <= prevSeq && prevSeq != 0 {
			t.Fatalf("seq not monotonic: %d after %d", ev.Seq, prevSeq)
		}
		prevSeq = ev.Seq
		if ev.Type == "service_detected" {
			detected++
		}
	}
	if detected != 2 {
		t.Fatalf("service_detected count = %d, want 2", detected)
	}
}

// TestRunnerFailedURLEmitsEvent verifies a failed URL probe (unreachable)
// still emits service_detected with status_code=0 + error and is recorded in
// result.Targets (B.3).
func TestRunnerFailedURLEmitsEvent(t *testing.T) {
	var buf bytes.Buffer
	emitter := event.NewEmitter(&buf)
	cfg := Config{
		Version:         "test",
		WorkDir:         t.TempDir(),
		TargetURL:       "http://127.0.0.1:1", // port 1 unreachable
		GonmapTimeout:   1,
		HTTPTimeoutSec:  2,
		HTTPConcurrency: 2,
		NoPOC:           true,
		RawArgs:         []string{"scan"},
	}
	result, err := NewRunner(cfg, &buf, emitter).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("result.Targets = %d, want 1 (failed probe recorded)", len(result.Targets))
	}
	if result.Targets[0].Error == "" {
		t.Fatal("expected non-empty error on failed probe")
	}
	if result.Targets[0].StatusCode != 0 {
		t.Fatalf("status = %d, want 0 on failed probe", result.Targets[0].StatusCode)
	}
	events := decodeScanEvents(t, &buf)
	var sawFailedEvent bool
	for _, ev := range events {
		if ev.Type == "service_detected" && ev.Data["error"] != nil && ev.Data["error"] != "" {
			sawFailedEvent = true
		}
	}
	if !sawFailedEvent {
		t.Fatal("expected a service_detected event carrying the probe error")
	}
}

// TestNucleiTargetsFiltersFailedProbes verifies that failed probes (Error!=""
// or StatusCode<=0) are NOT fed to nuclei (codex防坑点10).
func TestNucleiTargetsFiltersFailedProbes(t *testing.T) {
	services := []model.Service{
		{Host: "ok", URL: "http://ok/", StatusCode: 200, Error: ""},
		{Host: "fail1", URL: "http://fail1/", StatusCode: 0, Error: "dial timeout"},
		{Host: "fail2", URL: "http://fail2/", StatusCode: 0, Error: "connection refused"},
	}
	got := nucleiTargets(services)
	if len(got) != 1 {
		t.Fatalf("nucleiTargets = %v, want only [http://ok/]", got)
	}
	if got[0] != "http://ok/" {
		t.Fatalf("nucleiTargets[0] = %q, want http://ok/", got[0])
	}
}

// decodeScanEvents reads JSONL events from a buffer, skipping non-`{` lines.
func decodeScanEvents(t *testing.T, buf *bytes.Buffer) []event.Event {
	t.Helper()
	var out []event.Event
	sc := bufio.NewScanner(buf)
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event %q: %v", line, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	return out
}
