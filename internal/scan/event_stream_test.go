package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"github.com/CycSpring/SpringX-Scanner/internal/report"
)

// collectEvents runs a scan with an in-memory event buffer and returns all
// decoded events in emission order.
func collectEvents(t *testing.T, cfg Config) []event.Event {
	t.Helper()

	var buf bytes.Buffer
	emitter := event.NewEmitter(&buf)
	runner := NewRunner(cfg, &buf, emitter)

	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Simulate the CLI layer: write reports then emit report_written.
	paths, err := report.WriteAll(result, cfg.WorkDir)
	if err != nil {
		t.Fatalf("WriteAll returned error: %v", err)
	}
	runner.EmitReportWritten(paths)

	var events []event.Event
	scanner := bufio.NewScanner(&buf)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// In jsonl mode every line is an event; in mixed mode some lines are
		// human logs. Only decode lines that start with '{'.
		if line[0] != '{' {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("failed to decode event line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	return events
}

// eventTypes returns the ordered list of event types from a batch.
func eventTypes(events []event.Event) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.Type
	}
	return out
}

func TestEventStreamNucleiPOCFullChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/springx-smoke" {
			_, _ = w.Write([]byte("springx-smoke-ok"))
			return
		}
		_, _ = w.Write([]byte("<html><title>SpringX Event Smoke</title></html>"))
	}))
	defer server.Close()

	workDir := t.TempDir()
	cfg := Config{
		Version:       "test",
		WorkDir:       workDir,
		TargetURL:     server.URL,
		Ports:         "80",
		TemplateDir:   filepath.Join("..", "..", "testdata", "nuclei"),
		TempDir:       t.TempDir(),
		NucleiIDs:     []string{"springx-smoke"},
		GonmapTimeout: 2,
		LogFormat:     "jsonl",
		RawArgs:       []string{"scan", "-u", server.URL, "--jsonl-only"},
	}
	events := collectEvents(t, cfg)

	// --- Verify the full event chain is present and correctly ordered.
	types := eventTypes(events)

	required := []string{"scan_started", "poc_started", "vulnerability_found", "poc_completed", "scan_completed", "report_written"}
	lastIdx := -1
	for _, want := range required {
		idx := indexOf(types, want)
		if idx < 0 {
			t.Fatalf("event type %q missing from stream; got: %v", want, types)
		}
		if idx <= lastIdx {
			t.Fatalf("event %q appeared at index %d, before previous required event at %d; order: %v", want, idx, lastIdx, types)
		}
		lastIdx = idx
	}

	// --- Verify scan envelope consistency: find scan_started to anchor the scan_id.
	var scanStartedEv *event.Event
	for i := range events {
		if events[i].Type == "scan_started" {
			scanStartedEv = &events[i]
			break
		}
	}
	if scanStartedEv == nil {
		t.Fatal("scan_started event not found")
	}
	scanID, _ := scanStartedEv.Data["id"].(string)
	if scanID == "" {
		t.Fatalf("scan_started id is empty or wrong type: %v", scanStartedEv.Data["id"])
	}
	for i, ev := range events {
		if ev.Version != event.ProtocolVersion {
			t.Fatalf("event[%d] version = %q, want %q", i, ev.Version, event.ProtocolVersion)
		}
		if ev.ScanID != scanID {
			t.Fatalf("event[%d] (%s) scan_id = %q, want %q", i, ev.Type, ev.ScanID, scanID)
		}
		if ev.Seq == 0 {
			t.Fatalf("event[%d] (%s) has zero seq", i, ev.Type)
		}
		if i > 0 && ev.Seq <= events[i-1].Seq {
			t.Fatalf("event[%d] seq %d <= previous %d", i, ev.Seq, events[i-1].Seq)
		}
	}

	// --- Verify vulnerability_found payload matches the smoke finding.
	var vulnEv *event.Event
	for i := range events {
		if events[i].Type == "vulnerability_found" {
			vulnEv = &events[i]
			break
		}
	}
	if vulnEv == nil {
		t.Fatal("vulnerability_found not found (should have been caught above)")
	}
	if vulnEv.Data["engine"] != "nuclei" {
		t.Fatalf("vulnerability_found engine = %v, want nuclei", vulnEv.Data["engine"])
	}
	if vulnEv.Data["template_id"] != "springx-smoke" {
		t.Fatalf("vulnerability_found template_id = %v, want springx-smoke", vulnEv.Data["template_id"])
	}
	if vulnEv.Data["target"] == "" {
		t.Fatal("vulnerability_found target is empty")
	}

	// --- Verify poc_completed payload: findings count must equal 1.
	var pocEv *event.Event
	for i := range events {
		if events[i].Type == "poc_completed" {
			pocEv = &events[i]
			break
		}
	}
	if got := pocEv.Data["findings"]; got != float64(1) {
		t.Fatalf("poc_completed findings = %v, want 1", got)
	}
	if pocEv.Data["skipped"] != false {
		t.Fatalf("poc_completed skipped = %v, want false", pocEv.Data["skipped"])
	}
	if pocEv.Data["error"] != "" {
		t.Fatalf("poc_completed error = %v, want empty", pocEv.Data["error"])
	}

	// --- Verify report_written payload has all three paths and files exist.
	var reportEv *event.Event
	for i := range events {
		if events[i].Type == "report_written" {
			reportEv = &events[i]
			break
		}
	}
	for _, key := range []string{"html", "markdown", "json"} {
		path, ok := reportEv.Data[key].(string)
		if !ok || path == "" {
			t.Fatalf("report_written %s path missing or wrong type: %v", key, reportEv.Data[key])
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("report_written %s file does not exist: %s (%v)", key, path, err)
		}
	}

	// --- Cross-check: exactly one vulnerability_found event for one finding.
	count := 0
	for _, ev := range events {
		if ev.Type == "vulnerability_found" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 vulnerability_found event, got %d", count)
	}
}

func TestEventStreamNoPOCEmitsSkippedCompleted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>No POC</title></html>"))
	}))
	defer server.Close()

	workDir := t.TempDir()
	cfg := Config{
		Version:       "test",
		WorkDir:       workDir,
		TargetURL:     server.URL,
		Ports:         "80",
		NoPOC:         true,
		TempDir:       t.TempDir(),
		GonmapTimeout: 1,
		LogFormat:     "jsonl",
	}
	events := collectEvents(t, cfg)
	types := eventTypes(events)

	if indexOf(types, "scan_started") < 0 {
		t.Fatal("missing scan_started")
	}
	if indexOf(types, "poc_completed") < 0 {
		t.Fatal("missing poc_completed even when --nopoc")
	}

	// With --nopoc there must be NO vulnerability_found events.
	for _, ev := range events {
		if ev.Type == "vulnerability_found" {
			t.Fatal("vulnerability_found emitted under --nopoc")
		}
	}

	// poc_completed must report skipped=true.
	var pocEv *event.Event
	for i := range events {
		if events[i].Type == "poc_completed" {
			pocEv = &events[i]
			break
		}
	}
	if pocEv.Data["skipped"] != true {
		t.Fatalf("poc_completed skipped = %v, want true under --nopoc", pocEv.Data["skipped"])
	}
	if pocEv.Data["findings"] != float64(0) {
		t.Fatalf("poc_completed findings = %v, want 0 under --nopoc", pocEv.Data["findings"])
	}
}

func indexOf(slice []string, want string) int {
	for i, s := range slice {
		if s == want {
			return i
		}
	}
	return -1
}
