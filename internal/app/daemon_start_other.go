//go:build !darwin && !linux && !windows

package app

import (
	"context"
	"fmt"
)

func startDaemonProcess(context.Context) error {
	return fmt.Errorf("ssh-mcp daemon is unsupported on this platform")
}
