package web

import (
	"context"
	"testing"
)

// TestInterruptProcessExists verifies the platform-specific interruptProcess
// helper is wired and callable. The actual signal mechanism differs by
// platform (Ctrl-Break on Windows, SIGTERM on Unix) and is covered by the
// fake-child cancel test in scanmgr_test.go at the childProcess level. Here we
// only assert the builder links without starting a process.
func TestInterruptProcessHelpersExist(t *testing.T) {
	// A real child built with a valid context; we never Start it, so no process
	// is spawned. interruptProcess on a not-yet-started cmd is a no-op.
	cmd := newRealChild(context.Background(), "fake-exe", nil, "")
	if cmd == nil {
		t.Fatal("newRealChild returned nil")
	}
	if err := interruptProcess(cmd.cmd); err != nil {
		t.Fatalf("interruptProcess on unstarted cmd: %v", err)
	}
}
