//go:build smoke

package web

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
	"net/http"
	"net/http/httptest"
)

// TestSmokeRealScanFullChain builds the real springx.exe, runs it through the
// WebUI ScanManager against a local httptest target, and asserts the full event
// chain + on-disk report. This complements the fake-runner unit tests by
// exercising the real `springx scan --jsonl-only` child process end to end.
//
// Run with: go test -tags smoke ./internal/web/...
func TestSmokeRealScanFullChain(t *testing.T) {
	// 1. Build the real binary into a temp dir (os.Executable() inside go test
	//    returns the test binary, not springx.exe, so we must build our own).
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	exeName := "springx"
	if runtime.GOOS == "windows" {
		exeName = "springx.exe"
	}
	exePath := filepath.Join(t.TempDir(), exeName)
	build := exec.Command("go", "build", "-o", exePath, ".")
	build.Dir = repoRoot
	build.Env = append(os.Environ(),
		"GOFLAGS=",
	)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build springx.exe: %v\n%s", err, out)
	}

	// 2. Local target that the springx-smoke template matches.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/springx-smoke" {
			_, _ = w.Write([]byte("springx-smoke-ok"))
			return
		}
		_, _ = w.Write([]byte("<html><title>SpringX Smoke</title></html>"))
	}))
	defer server.Close()

	// 3. Absolute path to the nuclei test templates (the child's cwd is a temp
	//    WorkDir, so a relative ../.. path would not resolve).
	templateDir, err := filepath.Abs(filepath.Join(repoRoot, "testdata", "nuclei"))
	if err != nil {
		t.Fatalf("resolve template dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(templateDir, "springx-smoke.yaml")); err != nil {
		t.Fatalf("springx-smoke.yaml not found at %s: %v", templateDir, err)
	}

	workDir := t.TempDir()
	mgr := NewScanManager(ScanManagerOptions{
		ExePath: exePath,
		WorkDir: workDir,
	})

	// 4. Start the scan. NucleiIDs is a comma-joined string; GonmapTimeout keeps
	//    the TCP probe snappy.
	job, err := mgr.Start(context.Background(), ScanRequest{
		URL:               server.URL,
		NucleiIDs:         "springx-smoke",
		NucleiTemplateDir: templateDir,
		GonmapTimeout:     2,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// 5. Wait for the pump to finish (real nuclei POC can take a while).
	select {
	case <-job.done:
	case <-time.After(180 * time.Second):
		t.Fatal("scan did not finish within 180s")
	}

	// 6. Terminal status.
	if snap := job.snapshot(); snap.Status != StatusCompleted {
		t.Fatalf("status = %v, want completed", snap.Status)
	}

	// 7. Full event chain present and ordered.
	hist := job.history()
	types := make([]string, len(hist))
	for i, ev := range hist {
		types[i] = ev.Type
	}
	required := []string{"scan_started", "poc_started", "vulnerability_found", "poc_completed", "scan_completed", "report_written"}
	lastIdx := -1
	for _, want := range required {
		idx := indexOf(types, want)
		if idx < 0 {
			t.Fatalf("event %q missing; got: %v", want, types)
		}
		if idx <= lastIdx {
			t.Fatalf("event %q at %d before previous at %d; order: %v", want, idx, lastIdx, types)
		}
		lastIdx = idx
	}

	// 8. Envelope consistency: scan_id stable, seq monotonic.
	var scanID string
	for _, ev := range hist {
		if ev.Type == "scan_started" {
			scanID, _ = ev.Data["id"].(string)
			break
		}
	}
	if scanID == "" {
		t.Fatal("scan_started has no id")
	}
	for i, ev := range hist {
		if ev.ScanID != scanID {
			t.Fatalf("event[%d] (%s) scan_id = %q, want %q", i, ev.Type, ev.ScanID, scanID)
		}
		if ev.Seq == 0 {
			t.Fatalf("event[%d] (%s) zero seq", i, ev.Type)
		}
		if i > 0 && ev.Seq <= hist[i-1].Seq {
			t.Fatalf("event[%d] seq %d <= previous %d", i, ev.Seq, hist[i-1].Seq)
		}
	}

	// 9. vulnerability_found payload.
	var vulnCount int
	var vulnEv *event.Event
	for i := range hist {
		if hist[i].Type == "vulnerability_found" {
			vulnCount++
			vulnEv = &hist[i]
		}
	}
	if vulnCount != 1 {
		t.Fatalf("vulnerability_found count = %d, want 1", vulnCount)
	}
	if vulnEv.Data["engine"] != "nuclei" {
		t.Fatalf("vulnerability_found engine = %v", vulnEv.Data["engine"])
	}
	if vulnEv.Data["template_id"] != "springx-smoke" {
		t.Fatalf("vulnerability_found template_id = %v", vulnEv.Data["template_id"])
	}
	if vulnEv.Data["target"] == "" {
		t.Fatal("vulnerability_found target empty")
	}

	// 10. report_written: read the on-disk JSON and confirm 1 vulnerability.
	jsonPath := job.reportPaths.JSON
	if jsonPath == "" {
		t.Fatal("reportPaths.JSON is empty")
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report %s: %v", jsonPath, err)
	}
	var summary struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Scan            struct {
			ID string `json:"id"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(summary.Vulnerabilities) != 1 {
		t.Fatalf("report vulnerabilities = %d, want 1", len(summary.Vulnerabilities))
	}
	if summary.Scan.ID != scanID {
		t.Fatalf("report scan id = %q, want %q", summary.Scan.ID, scanID)
	}

	// 11. HTML + Markdown siblings exist.
	for _, p := range []string{job.reportPaths.HTML, job.reportPaths.Markdown} {
		if p == "" {
			t.Fatalf("report path empty: %+v", job.reportPaths)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("report sibling %s missing: %v", p, err)
		}
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
