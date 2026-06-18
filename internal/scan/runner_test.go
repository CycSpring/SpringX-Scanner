package scan

import (
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
