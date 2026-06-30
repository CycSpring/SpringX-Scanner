package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
)

// fakeChild is an injectable childProcess that emits a canned JSONL event
// stream on its stdout pipe, so scan-manager tests never need the real
// springx.exe binary (os.Executable() inside `go test` returns the test
// binary). Its Wait blocks until the scripted stream is consumed and the fake
// is signaled to exit.
type fakeChild struct {
	pr          *io.PipeReader
	pw          *io.PipeWriter
	mu          sync.Mutex
	started     bool
	waitCh      chan error
	killed      bool
	interrupted bool
	scripted    []event.Event
}

func newFakeChild(events []event.Event) *fakeChild {
	pr, pw := io.Pipe()
	return &fakeChild{
		pr:       pr,
		pw:       pw,
		waitCh:   make(chan error, 1),
		scripted: events,
	}
}

func (c *fakeChild) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return errors.New("already started")
	}
	c.started = true
	go func() {
		enc := json.NewEncoder(c.pw)
		for _, ev := range c.scripted {
			// Honor a kill/interrupt: stop writing once killed.
			c.mu.Lock()
			if c.killed {
				c.mu.Unlock()
				break
			}
			c.mu.Unlock()
			if err := enc.Encode(ev); err != nil {
				break // reader gone (e.g. cancel test)
			}
		}
		_ = c.pw.Close()
	}()
	return nil
}

func (c *fakeChild) Wait() error {
	// Block until the pipe writer closes (script done) or the test signals.
	select {
	case err := <-c.waitCh:
		return err
	case <-time.After(3 * time.Second):
		return errors.New("fake wait timeout")
	}
}

func (c *fakeChild) Stdout() io.Reader { return c.pr }

func (c *fakeChild) Interrupt() error {
	c.mu.Lock()
	c.interrupted = true
	c.mu.Unlock()
	// Closing the pipe ends the read loop; the pump synthesizes scan_failed
	// because no terminal event was emitted (mimicking a kill before report).
	_ = c.pw.CloseWithError(errors.New("interrupted"))
	c.waitCh <- errors.New("interrupted")
	return nil
}

func (c *fakeChild) Kill() error {
	c.mu.Lock()
	c.killed = true
	c.mu.Unlock()
	_ = c.pw.CloseWithError(errors.New("killed"))
	c.waitCh <- errors.New("killed")
	return nil
}

// scriptedEvents builds a full successful scan event chain in emission order.
func scriptedEvents(scanID string) []event.Event {
	return []event.Event{
		{Type: "scan_started", Data: map[string]any{"id": scanID, "args": []any{"scan", "-u", "http://x"}}},
		{Type: "target_discovered", Data: map[string]any{"url": "http://x"}},
		{Type: "service_detected", Data: map[string]any{"host": "x", "port": 80, "status_code": 200, "title": "X", "server": "nginx", "technologies": []any{"Nginx"}}},
		{Type: "poc_started", Data: map[string]any{"engine": "nuclei", "targets": 1}},
		{Type: "vulnerability_found", Data: map[string]any{"engine": "nuclei", "template_id": "springx-smoke", "severity": "info", "target": "http://x"}},
		{Type: "poc_completed", Data: map[string]any{"engine": "nuclei", "targets": 1, "findings": 1, "skipped": false}},
		{Type: "scan_completed", Data: map[string]any{"id": scanID, "status": "completed"}},
		{Type: "report_written", Data: map[string]any{"html": "/r/h.html", "markdown": "/r/m.md", "json": "/r/d.json"}},
	}
}

func newTestManager(t *testing.T, builder CommandBuilder) *ScanManager {
	t.Helper()
	return NewScanManager(ScanManagerOptions{
		ExePath: "fake-exe",
		WorkDir: t.TempDir(),
		Builder: builder,
	})
}

// TestScanManagerFullChain runs a fake scan and asserts the full event chain is
// parsed, cached, broadcast, and that job_id/scan_id mapping is established.
func TestScanManagerFullChain(t *testing.T) {
	scanID := "abc123"
	var child *fakeChild
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		child = newFakeChild(scriptedEvents(scanID))
		// Make Wait return immediately once the script is consumed.
		go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
		return child, nil
	})

	job, err := mgr.Start(context.Background(), ScanRequest{URL: "http://x"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if job.id == "" {
		t.Fatal("empty job_id")
	}

	// Subscribe before terminal to exercise live fan-out.
	sub := job.hub.subscribe()
	defer job.hub.unsubscribe(sub)

	// Wait for the pump to finish.
	select {
	case <-job.done:
	case <-time.After(3 * time.Second):
		t.Fatal("pump did not finish")
	}

	// job_id differs from engine scan_id (codex point #1).
	if job.scanID != scanID {
		t.Fatalf("scanID = %q, want %q", job.scanID, scanID)
	}
	if job.id == scanID {
		t.Fatal("job_id should differ from scan_id")
	}

	hist := job.history()
	types := make([]string, len(hist))
	for i, ev := range hist {
		types[i] = ev.Type
	}
	want := []string{"scan_started", "target_discovered", "service_detected", "poc_started", "vulnerability_found", "poc_completed", "scan_completed", "report_written"}
	if !equalSlice(types, want) {
		t.Fatalf("event types = %v, want %v", types, want)
	}

	// Report paths learned from report_written.
	if job.reportPaths.JSON != "/r/d.json" {
		t.Fatalf("reportPaths.JSON = %q", job.reportPaths.JSON)
	}

	// Terminal state.
	snap := job.snapshot()
	if snap.Status != StatusCompleted {
		t.Fatalf("status = %v, want completed", snap.Status)
	}
	if snap.ScanID != scanID {
		t.Fatalf("snapshot ScanID = %q, want %q", snap.ScanID, scanID)
	}

	// Live subscriber received at least the terminal report_written.
	gotTerminal := false
	for {
		select {
		case ev := <-sub.ordinary:
			if ev.Type == "report_written" {
				gotTerminal = true
			}
		case <-sub.terminal:
			gotTerminal = true
		case <-time.After(200 * time.Millisecond):
			if !gotTerminal {
				t.Fatal("subscriber did not receive terminal event")
			}
			return
		}
		if gotTerminal {
			return
		}
	}
}

// TestScanManagerReplay asserts a late subscriber recovers the full history
// from the cache (codex point #4).
func TestScanManagerReplay(t *testing.T) {
	scanID := "replay123"
	var child *fakeChild
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		child = newFakeChild(scriptedEvents(scanID))
		go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
		return child, nil
	})

	job, _ := mgr.Start(context.Background(), ScanRequest{URL: "http://x"})
	<-job.done

	// Late subscriber: history replay must include every event.
	got := job.history()
	if len(got) != 8 {
		t.Fatalf("replay got %d events, want 8", len(got))
	}
	if got[0].Type != "scan_started" || got[7].Type != "report_written" {
		t.Fatalf("replay order wrong: %s ... %s", got[0].Type, got[7].Type)
	}
}

// TestScanManagerCancelInterrupts asserts Cancel triggers Interrupt on the
// child and the job reaches a terminal state (codex point #2).
func TestScanManagerCancelInterrupts(t *testing.T) {
	// Script that never emits a terminal event on its own.
	blocking := []event.Event{
		{Type: "scan_started", Data: map[string]any{"id": "c1"}},
		{Type: "target_discovered", Data: map[string]any{"url": "http://x"}},
	}
	var child *fakeChild
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		child = newFakeChild(blocking)
		return child, nil
	})

	job, _ := mgr.Start(context.Background(), ScanRequest{URL: "http://x"})

	// Give the pump a moment to read the two scripted events.
	time.Sleep(80 * time.Millisecond)

	if err := mgr.Cancel(job.id); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	select {
	case <-job.done:
	case <-time.After(3 * time.Second):
		t.Fatal("pump did not finish after cancel")
	}

	if !job.isTerminal() {
		t.Fatal("job not terminal after cancel")
	}
	if !child.interrupted {
		t.Fatal("child.Interrupt was not called")
	}
}

func TestScanManagerUsesConfiguredWorkDir(t *testing.T) {
	workDir := t.TempDir()
	var gotWorkDir string
	mgr := NewScanManager(ScanManagerOptions{
		ExePath: "fake-exe",
		WorkDir: workDir,
		Builder: func(ctx context.Context, exePath string, args []string) (childProcess, error) {
			child := newFakeChild(scriptedEvents("wd1"))
			go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
			gotWorkDir = workDir
			return child, nil
		},
	})
	job, err := mgr.Start(context.Background(), ScanRequest{URL: "http://x"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.done
	if gotWorkDir != workDir {
		t.Fatalf("builder work dir = %q, want %q", gotWorkDir, workDir)
	}
}

func TestScanManagerDetachesFromRequestContext(t *testing.T) {
	var child *fakeChild
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		child = newFakeChild(scriptedEvents("ctx1"))
		go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
		return child, nil
	})

	reqCtx, cancel := context.WithCancel(context.Background())
	job, err := mgr.Start(reqCtx, ScanRequest{URL: "http://x"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()

	select {
	case <-job.done:
	case <-time.After(3 * time.Second):
		t.Fatal("pump did not finish")
	}
	if job.snapshot().Status != StatusCompleted {
		t.Fatalf("job status = %s, want completed", job.snapshot().Status)
	}
	if child.interrupted || child.killed {
		t.Fatalf("request context cancellation should not interrupt child: interrupted=%v killed=%v", child.interrupted, child.killed)
	}
}

func TestBuildScanArgs(t *testing.T) {
	args := buildScanArgs(ScanRequest{
		URL: "http://x", Ports: "TOP100", Threads: 5, NoPOC: true,
		NucleiSeverity: "critical,high",
	})
	// --jsonl-only and --web/--no-browser always present.
	if !contains(args, "--jsonl-only") || !contains(args, "--web") || !contains(args, "--no-browser") {
		t.Fatalf("missing required flags: %v", args)
	}
	if !contains(args, "--nopoc") {
		t.Fatalf("missing --nopoc: %v", args)
	}
	if !contains(args, "critical,high") {
		t.Fatalf("missing nuclei severity: %v", args)
	}
	// No-op compat flags must not appear.
	for _, bad := range []string{"--dbs", "--risk", "--deep-scan", "--nocrack"} {
		if contains(args, bad) {
			t.Fatalf("no-op compat flag leaked: %s in %v", bad, args)
		}
	}
}

// TestBuildScanArgsOmitsZeroes ensures empty/zero values are skipped so the
// scanner uses its own defaults.
func TestBuildScanArgsOmitZeroes(t *testing.T) {
	args := buildScanArgs(ScanRequest{URL: "http://x"})
	if contains(args, "-p") || contains(args, "-t") || contains(args, "-x") {
		t.Fatalf("zero/empty flags should be omitted: %v", args)
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestSSENoDuplicateOnReplayRace exercises the codex P1 fix end-to-end through
// a real HTTP/SSE response. It drives a fake scan to completion with distinct
// seqs, then connects a late SSE subscriber and asserts that every event type
// appears exactly once in the SSE output — in particular that
// report_written is neither dropped (the lastSeq<= regression) nor duplicated.
func TestSSENoDuplicateOnReplayRace(t *testing.T) {
	scanID := "dedup1"
	events := scriptedEvents(scanID)
	// The fake child bypasses the Emitter, so assign distinct seqs by hand to
	// mirror what a real scan produces (Emitter assigns seq >= 1).
	for i := range events {
		events[i].Seq = uint64(i) + 1
	}
	srv := newTestServer(t, func() []event.Event {
		// Copy so each call returns its own slice with the preset seqs.
		out := make([]event.Event, len(events))
		copy(out, events)
		return out
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Start the scan.
	body := strings.NewReader(`{"url":"http://x"}`)
	resp, err := ts.Client().Post(ts.URL+"/api/scan", "application/json", body)
	if err != nil {
		t.Fatalf("POST /api/scan: %v", err)
	}
	var sr scanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode scan response: %v", err)
	}
	resp.Body.Close()

	// Subscribe via SSE after the scan is done (late subscriber = replay path).
	<-mgrDone(srv, sr.JobID)
	res, err := ts.Client().Get(ts.URL + "/api/events?id=" + sr.JobID)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read SSE body: %v", err)
	}

	// Count each event type in the SSE output; every type must appear exactly once.
	counts := countSSEEventTypes(string(data))
	want := []string{
		"scan_started", "target_discovered", "service_detected",
		"poc_started", "vulnerability_found", "poc_completed",
		"scan_completed", "report_written",
	}
	for _, ty := range want {
		if counts[ty] != 1 {
			t.Fatalf("SSE event %q appeared %d times, want 1\noutput: %s", ty, counts[ty], string(data))
		}
	}
}

// mgrDone returns a channel that closes when the job's pump has finished.
func mgrDone(srv *Server, jobID string) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		// Poll briefly until the job is known and its pump done.
		for i := 0; i < 200; i++ {
			if j := srv.mgr.Get(jobID); j != nil {
				select {
				case <-j.done:
					return
				default:
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return ch
}

// countSSEEventTypes parses SSE `data: {...}` lines and tallies the `type`
// field of each event.
func countSSEEventTypes(s string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal([]byte(line[len("data: "):]), &ev); err != nil {
			continue
		}
		out[ev.Type]++
	}
	return out
}
