//go:build darwin || linux

package app

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"ssh-mcp/internal/bridge"
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
	if err := syscall.Kill(marker.PID, 0); errors.Is(err, syscall.ESRCH) {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect ssh-mcp daemon: %w", err)
	}
	matches, alive, err := daemonMarkerState(marker)
	if err != nil {
		return false, err
	}
	if !alive {
		return true, nil
	}
	if !matches {
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
	matches, alive, err := daemonMarkerState(marker)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	if !matches {
		return errDaemonPIDMismatch
	}
	if err := syscall.Kill(marker.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("force stop ssh-mcp daemon: %w", err)
	}
	return nil
}

func daemonMarkerState(marker daemonPIDMarker) (matches, alive bool, err error) {
	startTime, err := bridge.ProcessStartTime(marker.PID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("resolve ssh-mcp daemon identity: %w", err)
	}
	return startTime == marker.StartTime, true, nil
}

func cleanupStoppedDaemonArtifacts(socketPath, pidPath string, expected daemonPIDMarker) error {
	var result error
	if info, err := os.Lstat(socketPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("inspect stopped daemon endpoint: %w", err))
		}
	} else if info.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove stopped daemon endpoint: %w", err))
		}
	}
	if err := removeDaemonPID(pidPath, expected); err != nil {
		result = errors.Join(result, fmt.Errorf("remove stopped daemon PID: %w", err))
	}
	return result
}
