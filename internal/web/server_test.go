package web

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
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
)

// newTestServer builds a Server whose ScanManager uses a fake builder returning
// the given scripted events.
func newTestServer(t *testing.T, scripted func() []event.Event) *Server {
	t.Helper()
	srv, err := NewServer(Options{
		WorkDir: t.TempDir(),
		ExePath: "fake-exe",
		Builder: func(ctx context.Context, exePath string, args []string) (childProcess, error) {
			child := newFakeChild(scripted())
			go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
			return child, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// TestServerStartScanAndSSE triggers a scan via the API, subscribes to the SSE
// stream, and asserts events flow through to the client.
func TestServerStartScanAndSSE(t *testing.T) {
	srv := newTestServer(t, func() []event.Event { return scriptedEvents("e2e1") })
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// POST /api/scan
	body := strings.NewReader(`{"url":"http://x"}`)
	resp, err := ts.Client().Post(ts.URL+"/api/scan", "application/json", body)
	if err != nil {
		t.Fatalf("POST /api/scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var sr scanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode scan response: %v", err)
	}
	if sr.JobID == "" {
		t.Fatal("empty job_id")
	}

	// GET /api/events (SSE) — read until the terminal scan_completed arrives.
	eventsURL := ts.URL + "/api/events?id=" + sr.JobID
	res, err := ts.Client().Get(eventsURL)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content-type = %q", res.Header.Get("Content-Type"))
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read SSE body: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "data: ") {
		t.Fatalf("no SSE data lines: %q", got)
	}
	if !strings.Contains(got, "scan_completed") {
		t.Fatalf("missing scan_completed in stream: %q", got)
	}
	if !strings.Contains(got, "report_written") {
		t.Fatalf("missing report_written in stream: %q", got)
	}
}

// TestServerListScans returns the running job.
func TestServerListScans(t *testing.T) {
	srv := newTestServer(t, func() []event.Event {
		// A scan that "hangs" (no terminal event) so it stays running for the list.
		return []event.Event{{Type: "scan_started", Data: map[string]any{"id": "ls1"}}}
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := strings.NewReader(`{"url":"http://x"}`)
	resp, err := ts.Client().Post(ts.URL+"/api/scan", "application/json", body)
	if err != nil {
		t.Fatalf("POST /api/scan: %v", err)
	}
	var sr scanResponse
	_ = json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()

	// GET /api/scans
	res, err := ts.Client().Get(ts.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans: %v", err)
	}
	defer res.Body.Close()
	var list []jobSnapshot
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, j := range list {
		if j.JobID == sr.JobID {
			found = true
		}
	}
	if !found {
		t.Fatalf("job %s not in list %v", sr.JobID, list)
	}
}

// TestServerReportsPathSafety verifies the reports API rejects path traversal
// (codex point #5).
func TestServerReportsPathSafety(t *testing.T) {
	srv, err := NewServer(Options{WorkDir: t.TempDir(), ExePath: "fake"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Seed a legit report file.
	dataDir := filepath.Join(srv.workDir, "reports", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legit := filepath.Join(dataDir, "SpringX-Scan-ok.json")
	if err := os.WriteFile(legit, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"legit basename", "/api/reports/SpringX-Scan-ok.json", http.StatusOK},
		{"parent traversal", "/api/reports/" + urlEscape(".."), http.StatusBadRequest},
		{"absolute-ish path", "/api/reports/" + urlEscape("/etc/passwd"), http.StatusBadRequest},
		{"missing", "/api/reports/does-not-exist.json", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ts.Client().Get(ts.URL + tc.url)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.url, err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("GET %s: status = %d, want %d", tc.url, res.StatusCode, tc.want)
			}
		})
	}

	// List reports returns the legit file.
	res, err := ts.Client().Get(ts.URL + "/api/reports")
	if err != nil {
		t.Fatalf("GET /api/reports: %v", err)
	}
	defer res.Body.Close()
	var items []reportListItem
	if err := json.NewDecoder(res.Body).Decode(&items); err != nil {
		t.Fatalf("decode reports: %v", err)
	}
	if len(items) != 1 || items[0].Name != "SpringX-Scan-ok.json" {
		t.Fatalf("reports = %+v", items)
	}
}

// TestServerHealth verifies the liveness probe.
func TestServerHealth(t *testing.T) {
	srv, err := NewServer(Options{WorkDir: t.TempDir(), ExePath: "fake"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

// TestServerIndexServesHTML verifies the SPA shell is served at /.
func TestServerIndexServesHTML(t *testing.T) {
	srv, err := NewServer(Options{WorkDir: t.TempDir(), ExePath: "fake"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
}

// TestServerTemplatesIgnoresDirFromRequest verifies that neither
// GET /api/templates?dir=... nor POST /api/templates/pull with a body "dir"
// can override the target directory. This prevents an attacker from using
// --force to os.RemoveAll an arbitrary path via the WebUI API.
func TestServerTemplatesIgnoresDirFromRequest(t *testing.T) {
	srv, err := NewServer(Options{WorkDir: t.TempDir(), ExePath: "fake"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. GET /api/templates?dir=D:\evil must still report the default dir.
	res, err := ts.Client().Get(ts.URL + "/api/templates?dir=D%3A%5CEvil")
	if err != nil {
		t.Fatalf("GET /api/templates: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var getResp struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(res.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	expected := srv.defaultTemplateDir()
	if getResp.Dir != expected {
		t.Fatalf("GET /api/templates?dir=... returned dir %q, want %q (should ignore query param)", getResp.Dir, expected)
	}

	// 2. POST /api/templates/pull with {"dir":"D:\\evil","force":false} must NOT
	//    use the evil dir. We seed the default dir with a stray file so the pull
	//    refuses (non-empty, non-git) without touching the network. The error
	//    should reference the default pocs/nuclei dir, not "D:\evil".
	defaultDir := srv.defaultTemplateDir()
	if err := os.MkdirAll(defaultDir, 0o755); err != nil {
		t.Fatalf("mkdir default dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(defaultDir, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	body := strings.NewReader(`{"dir":"D:\\Evil","force":false}`)
	res2, err := ts.Client().Post(ts.URL+"/api/templates/pull", "application/json", body)
	if err != nil {
		t.Fatalf("POST /api/templates/pull: %v", err)
	}
	defer res2.Body.Close()
	// The pull will fail (non-empty non-git dir), which is expected.
	var pullResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(res2.Body).Decode(&pullResp); err != nil {
		t.Fatalf("decode pull response: %v", err)
	}
	if strings.Contains(pullResp.Error, "Evil") {
		t.Fatalf("pull error should not reference the ignored dir, got: %q", pullResp.Error)
	}
	if !strings.Contains(pullResp.Error, "pocs") {
		t.Fatalf("pull error should reference the default pocs/nuclei dir, got: %q", pullResp.Error)
	}
}

func urlEscape(s string) string {
	// Minimal percent-encoding for the test path segments.
	var b strings.Builder
	for _, r := range s {
		if r == '/' || r == '.' {
			b.WriteString("%" + hex(byte(r)))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func hex(b byte) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[b>>4], h[b&0xf]})
}
