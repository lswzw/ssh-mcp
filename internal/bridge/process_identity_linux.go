//go:build linux

package bridge

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProcessWorkingDirectory(pid int) string {
	if pid <= 0 {
		return ""
	}
	directory, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
	if err != nil {
		return ""
	}
	return directory
}

func platformProcessStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, ErrUnauthorized
	}
	value, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// The comm field may contain ')', so find the final delimiter before
	// splitting the fields that follow it.
	end := strings.LastIndex(string(value), ")")
	if end < 0 {
		return 0, ErrUnauthorized
	}
	fields := strings.Fields(string(value[end+1:]))
	if len(fields) <= 19 {
		return 0, ErrUnauthorized
	}
	startedAt, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startedAt == 0 {
		return 0, ErrUnauthorized
	}
	return startedAt, nil
}
