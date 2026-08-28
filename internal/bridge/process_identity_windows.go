//go:build windows

package bridge

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func platformProcessWorkingDirectory(int) string {
	// Windows has no supported equivalent of /proc/<pid>/cwd. Keep this as
	// optional audit metadata instead of guessing from the executable path.
	return ""
}

func platformProcessStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, ErrUnauthorized
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("open process for identity: %w", err)
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, fmt.Errorf("query process start time: %w", err)
	}
	value := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if value == 0 {
		return 0, ErrUnauthorized
	}
	return value, nil
}
