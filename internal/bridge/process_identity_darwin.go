//go:build darwin

package bridge

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func platformProcessWorkingDirectory(int) string {
	// Darwin does not expose another process' cwd through the portable Go
	// APIs. This field is audit metadata; authorization uses the start time.
	return ""
}

func platformProcessStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, ErrUnauthorized
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("query process start time: %w", err)
	}
	start := process.Proc.P_starttime
	if start.Sec <= 0 {
		return 0, ErrUnauthorized
	}
	return uint64(start.Sec)*1_000_000 + uint64(start.Usec), nil
}
