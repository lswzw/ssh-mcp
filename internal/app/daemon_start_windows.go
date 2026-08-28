//go:build windows

package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Windows does not support ExtraFiles. Readiness is therefore established by
// the authenticated local transport probe in waitForReadyDaemon, rather than
// by inheriting a Unix file descriptor into the child.
func startDaemonProcess(context.Context) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve ssh-mcp executable: %w", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open daemon output sink: %w", err)
	}
	defer devNull.Close()
	command := exec.Command(executable, "daemon")
	command.Stdout = devNull
	command.Stderr = devNull
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start ssh-mcp daemon: %w", err)
	}
	return command.Process.Release()
}
