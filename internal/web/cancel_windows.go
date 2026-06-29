//go:build windows

package web

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// configureProcessGroup starts the child in its own console process group so
// that GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) targets only the child
// and never the WebUI process. os.Interrupt is not deliverable to Windows child
// processes, so Ctrl-Break is the only graceful path.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
}

// interruptProcess asks the child to stop gracefully. On Windows it sends a
// CTRL_BREAK_EVENT to the child's process group (the Go runtime maps this to
// os.Interrupt inside the child, so scan.go's signal.NotifyContext fires and
// the scan finishes with status "stopped" and still emits report_written).
func interruptProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
}
