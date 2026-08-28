//go:build windows

package app

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func daemonProcessExited(pidPath string) (bool, error) {
	marker, err := readDaemonPID(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return daemonProcessExitedMarker(marker)
}

func daemonProcessExitedMarker(marker daemonPIDMarker) (bool, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(marker.PID))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return true, nil
		}
		return false, fmt.Errorf("open ssh-mcp daemon: %w", err)
	}
	defer windows.CloseHandle(handle)
	state, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, fmt.Errorf("inspect ssh-mcp daemon: %w", err)
	}
	if state == windows.WAIT_OBJECT_0 {
		return true, nil
	}
	startTime, err := processStartTimeFromHandle(handle)
	if err != nil {
		return false, err
	}
	if startTime != marker.StartTime {
		return false, errDaemonPIDMismatch
	}
	return false, nil
}

func forceStopDaemonProcess(pidPath string) error {
	marker, err := readDaemonPID(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return forceStopDaemonMarker(marker)
}

func forceStopDaemonMarker(marker daemonPIDMarker) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(marker.PID))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open ssh-mcp daemon for forced stop: %w", err)
	}
	defer windows.CloseHandle(handle)
	state, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return fmt.Errorf("inspect ssh-mcp daemon before forced stop: %w", err)
	}
	if state == windows.WAIT_OBJECT_0 {
		return nil
	}
	startTime, err := processStartTimeFromHandle(handle)
	if err != nil {
		return err
	}
	if startTime != marker.StartTime {
		return errDaemonPIDMismatch
	}
	if err := windows.TerminateProcess(handle, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("force stop ssh-mcp daemon: %w", err)
	}
	return nil
}

func processStartTimeFromHandle(handle windows.Handle) (uint64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, fmt.Errorf("resolve ssh-mcp daemon identity: %w", err)
	}
	value := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if value == 0 {
		return 0, errDaemonPIDMismatch
	}
	return value, nil
}

func cleanupStoppedDaemonArtifacts(_ string, pidPath string, expected daemonPIDMarker) error {
	// Named pipes disappear when their server closes; only the PID marker is a
	// filesystem artifact on Windows.
	if err := removeDaemonPID(pidPath, expected); err != nil {
		return fmt.Errorf("remove stopped daemon PID: %w", err)
	}
	return nil
}
