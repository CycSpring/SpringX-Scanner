//go:build !windows

package web

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup is a no-op on Unix; signals are delivered by PID.
func configureProcessGroup(cmd *exec.Cmd) {}

// interruptProcess asks the child to stop gracefully with SIGTERM (scan.go
// listens for os.Interrupt and syscall.SIGTERM). Cancel owns the grace wait
// and force-kill fallback.
func interruptProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}
