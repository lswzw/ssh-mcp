//go:build windows

package terminal

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureWindowsConsole(command *exec.Cmd) error {
	if command == nil {
		return ErrInvalidConfiguration
	}
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	return nil
}
