//go:build !windows

package terminal

import "os/exec"

func configureWindowsConsole(*exec.Cmd) error { return ErrInvalidConfiguration }
