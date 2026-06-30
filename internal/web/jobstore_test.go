package web

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CycSpring/SpringX-Scanner/internal/event"
)

// TestJobStoreSaveLoadDelete exercises the persistence round-trip: save a job,
// load it back, and confirm the tombstone fields survive; then delete it.
func TestJobStoreSaveLoadDelete(t *testing.T) {
	workDir := t.TempDir()

	// Build an in-memory terminal job directly.
	j := &ScanJob{
		id:         "job-deadbeef",
		startedAt:  time.Now().Add(-1 * time.Hour),
		finishedAt: time.Now().Add(-30 * time.Minute),
		args:       []string{"scan", "-u", "http://x"},
		scanID:     "engine123",
		status:     StatusCompleted,
		history_:   scriptedEvents("engine123"),
		hub:        newHub(),
		done:       closedChan(),
	}
	j.reportPaths = decodeReportPaths(j.history_[7].Data)

	if err := saveJob(workDir, j); err != nil {
		t.Fatalf("saveJob: %v", err)
	}

	// File exists at the expected path.
	path := jobFilePath(workDir, j.id)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persisted file missing: %v", err)
	}

	// Load it back.
	loaded, err := loadJobs(workDir)
	if err != nil {
		t.Fatalf("loadJobs: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d jobs, want 1", len(loaded))
	}
	got := loaded[0]
	if got.id != j.id {
		t.Fatalf("id = %q, want %q", got.id, j.id)
	}
	if got.scanID != j.scanID {
		t.Fatalf("scanID = %q, want %q", got.scanID, j.scanID)
	}
	if got.status != StatusCompleted {
		t.Fatalf("status = %v, want completed", got.status)
	}
	if got.reportPaths.JSON != "/r/d.json" {
		t.Fatalf("reportPaths.JSON = %q", got.reportPaths.JSON)
	}
	if len(got.history_) != len(j.history_) {
		t.Fatalf("history len = %d, want %d", len(got.history_), len(j.history_))
	}
	// Tombstone: done is closed, proc is nil.
	select {
	case <-got.done:
	default:
		t.Fatal("loaded job done channel not closed")
	}
	if got.proc != nil {
		t.Fatal("loaded job proc should be nil")
	}

	// Delete it.
	if err := deleteJob(workDir, j.id); err != nil {
		t.Fatalf("deleteJob: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete: %v", err)
	}
	// Delete again is a no-op (not an error).
	if err := deleteJob(workDir, j.id); err != nil {
		t.Fatalf("deleteJob on missing: %v", err)
	}
}

// TestJobStoreLoadSkipsCorrupt confirms malformed files are skipped, not fatal.
func TestJobStoreLoadSkipsCorrupt(t *testing.T) {
	workDir := t.TempDir()
	dir := jobsDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A valid file.
	valid := &ScanJob{
		id: "job-abc123def456", startedAt: time.Now(), finishedAt: time.Now(),
		status: StatusCompleted, hub: newHub(), done: closedChan(),
	}
	if err := saveJob(workDir, valid); err != nil {
		t.Fatal(err)
	}
	// A corrupt file.
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-job extension file (should be ignored).
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadJobs(workDir)
	if err != nil {
		t.Fatalf("loadJobs: %v", err)
	}
	if len(loaded) != 1 || loaded[0].id != "job-abc123def456" {
		t.Fatalf("loaded = %+v, want only job-abc123def456", loaded)
	}
}

// TestJobStoreLoadEmpty confirms a missing jobs dir is not an error.
func TestJobStoreLoadEmpty(t *testing.T) {
	loaded, err := loadJobs(t.TempDir())
	if err != nil {
		t.Fatalf("loadJobs on missing dir: %v", err)
	}
	if loaded != nil && len(loaded) != 0 {
		t.Fatalf("expected nil/empty, got %v", loaded)
	}
}

// TestScanManagerPersistsTerminalJob runs a fake scan to completion and asserts
// a job snapshot is written to reports/jobs/<job_id>.json.
func TestScanManagerPersistsTerminalJob(t *testing.T) {
	scanID := "persist1"
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		child := newFakeChild(scriptedEvents(scanID))
		go func() { <-time.After(50 * time.Millisecond); child.waitCh <- nil }()
		return child, nil
	})

	job, _ := mgr.Start(context.Background(), ScanRequest{URL: "http://x"})
	<-job.done

	// The persisted snapshot must exist.
	path := jobFilePath(mgr.workDir, job.id)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persisted job snapshot missing: %v", err)
	}
	loaded, err := loadJobs(mgr.workDir)
	if err != nil {
		t.Fatalf("loadJobs: %v", err)
	}
	var found bool
	for _, j := range loaded {
		if j.id == job.id {
			found = true
			if j.status != StatusCompleted {
				t.Fatalf("persisted status = %v", j.status)
			}
			if j.scanID != scanID {
				t.Fatalf("persisted scanID = %q, want %q", j.scanID, scanID)
			}
		}
	}
	if !found {
		t.Fatalf("job %s not in persisted set", job.id)
	}
}

// TestScanManagerLoadsJobsOnStart confirms a pre-written job appears in List()
// after constructing a new manager (simulating a restart).
func TestScanManagerLoadsJobsOnStart(t *testing.T) {
	workDir := t.TempDir()
	// Pre-seed a persisted job.
	seed := &ScanJob{
		id: "job-feedfacedead", startedAt: time.Now().Add(-1 * time.Hour),
		finishedAt: time.Now().Add(-30 * time.Minute), scanID: "old1",
		status: StatusCompleted, hub: newHub(), done: closedChan(),
	}
	if err := saveJob(workDir, seed); err != nil {
		t.Fatal(err)
	}

	// New manager loads persisted jobs.
	mgr := NewScanManager(ScanManagerOptions{ExePath: "fake-exe", WorkDir: workDir})
	list := mgr.List()
	var found bool
	for _, s := range list {
		if s.JobID == "job-feedfacedead" {
			found = true
			if s.ScanID != "old1" || s.Status != StatusCompleted {
				t.Fatalf("loaded snapshot = %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("pre-seeded job not loaded on start")
	}
}

// TestScanManagerReaperRemovesExpiredJob constructs an expired terminal job
// and confirms reapExpired removes it (and its persisted snapshot), while a
// fresh terminal job is kept.
func TestScanManagerReaperRemovesExpiredJob(t *testing.T) {
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		t.Fatal("reaper test should not start scans")
		return nil, nil
	})

	expired := &ScanJob{
		id: "job-1a2b3c4d5e6f", startedAt: time.Now().Add(-2 * time.Hour),
		finishedAt: time.Now().Add(-90 * time.Minute), scanID: "e1",
		status: StatusCompleted, hub: newHub(), done: closedChan(), mgr: mgr,
	}
	fresh := &ScanJob{
		id: "job-0fedcba98765", startedAt: time.Now().Add(-1 * time.Minute),
		finishedAt: time.Now().Add(-30 * time.Second), scanID: "f1",
		status: StatusCompleted, hub: newHub(), done: closedChan(), mgr: mgr,
	}
	// Also a still-running job — must never be reaped.
	running := &ScanJob{
		id: "job-running", startedAt: time.Now(),
		scanID: "r1", status: StatusRunning, hub: newHub(),
		done: make(chan struct{}), mgr: mgr,
	}
	for _, j := range []*ScanJob{expired, fresh, running} {
		mgr.mu.Lock()
		mgr.jobs[j.id] = j
		mgr.mu.Unlock()
		// Persist the terminal ones so we can assert disk cleanup.
		if j.status.terminal() {
			_ = saveJob(mgr.workDir, j)
		}
	}

	// ttl = 1 hour: expired (90m ago) is reaped, fresh (30s ago) and running kept.
	mgr.reapExpired(1 * time.Hour)

	if mgr.Get("job-1a2b3c4d5e6f") != nil {
		t.Error("expired job was not reaped")
	}
	if _, err := os.Stat(jobFilePath(mgr.workDir, "job-1a2b3c4d5e6f")); !os.IsNotExist(err) {
		t.Error("expired job snapshot file was not deleted")
	}
	if mgr.Get("job-0fedcba98765") == nil {
		t.Error("fresh job was wrongly reaped")
	}
	if mgr.Get("job-running") == nil {
		t.Error("running job was wrongly reaped")
	}
}

// TestScanManagerReaperSkipsActiveSubscriber confirms a terminal job with an
// active SSE subscriber is not reaped even if expired.
func TestScanManagerReaperSkipsActiveSubscriber(t *testing.T) {
	mgr := newTestManager(t, func(ctx context.Context, exePath string, args []string) (childProcess, error) {
		return nil, nil
	})
	expiredWithSub := &ScanJob{
		id: "job-9a8b7c6d5e4f", startedAt: time.Now().Add(-2 * time.Hour),
		finishedAt: time.Now().Add(-90 * time.Minute), scanID: "s1",
		status: StatusCompleted, hub: newHub(), done: closedChan(), mgr: mgr,
	}
	mgr.mu.Lock()
	mgr.jobs[expiredWithSub.id] = expiredWithSub
	mgr.mu.Unlock()
	// Hold an active subscriber.
	sub := expiredWithSub.hub.subscribe()
	defer expiredWithSub.hub.unsubscribe(sub)

	mgr.reapExpired(1 * time.Hour)
	if mgr.Get("job-9a8b7c6d5e4f") == nil {
		t.Error("job with active subscriber was wrongly reaped")
	}
}

// TestSSEHubCount verifies the subscriber-count helper used by the reaper.
func TestSSEHubCount(t *testing.T) {
	h := newHub()
	if c := h.count(); c != 0 {
		t.Fatalf("initial count = %d, want 0", c)
	}
	s1 := h.subscribe()
	if c := h.count(); c != 1 {
		t.Fatalf("count = %d, want 1", c)
	}
	s2 := h.subscribe()
	if c := h.count(); c != 2 {
		t.Fatalf("count = %d, want 2", c)
	}
	h.unsubscribe(s1)
	h.unsubscribe(s2)
	if c := h.count(); c != 0 {
		t.Fatalf("final count = %d, want 0", c)
	}
}

// ensure scriptedEvents is referenced (avoids unused import false-positive in
// some build configs) — it is used by other tests in scanmgr_test.go already.
var _ = event.ProtocolVersion

// TestDeleteJobRejectsTraversalID confirms a crafted job_id cannot escape the
// jobs directory via path traversal (codex P2). deleteJob must be a no-op for
// any id that is not ^job-[0-9a-f]+$.
func TestDeleteJobRejectsTraversalID(t *testing.T) {
	workDir := t.TempDir()
	// Seed a real file outside the jobs dir that a naive traversal would delete.
	target := filepath.Join(workDir, "secret.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		".." + string(filepath.Separator) + "secret", // parent traversal
		"job-",        // empty hex
		"job-xyz",     // non-hex
		"job-abc.txt", // extension injection
	} {
		if err := deleteJob(workDir, bad); err != nil {
			t.Errorf("deleteJob(%q) returned error %v, want nil no-op", bad, err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("deleteJob(%q) deleted the target file — traversal succeeded", bad)
		}
	}
}

// TestSaveJobRejectsInvalidID confirms an invalid job_id is never written to a
// path derived from it.
func TestSaveJobRejectsInvalidID(t *testing.T) {
	workDir := t.TempDir()
	j := &ScanJob{
		id: ".." + string(filepath.Separator) + "evil", startedAt: time.Now(),
		finishedAt: time.Now(), status: StatusCompleted, hub: newHub(), done: closedChan(),
	}
	if err := saveJob(workDir, j); err != nil {
		t.Fatalf("saveJob: %v", err)
	}
	// No file should have been created under jobs/ (saveJob is a no-op).
	if _, err := os.Stat(jobsDir(workDir)); !os.IsNotExist(err) {
		t.Fatalf("jobs dir should not exist, saveJob should have been a no-op: %v", err)
	}
}

// TestLoadJobsRejectsFilenameMismatch confirms a file whose name does not match
// a valid job id, or whose body id differs from the filename, is skipped.
func TestLoadJobsRejectsFilenameMismatch(t *testing.T) {
	workDir := t.TempDir()
	dir := jobsDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A valid-hex filename but a body whose id differs — must not load.
	mismatch := []byte(`{"job_id":"job-deadbeef","status":"completed","started_at":"2026-01-01T00:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(dir, "job-cafebabe.json"), mismatch, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadJobs(workDir)
	if err != nil {
		t.Fatalf("loadJobs: %v", err)
	}
	for _, j := range loaded {
		if j.id == "job-deadbeef" {
			t.Fatalf("loaded mismatched job (body id != filename)")
		}
	}
}
