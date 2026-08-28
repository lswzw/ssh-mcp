//go:build !darwin && !linux && !windows

package app

import (
	"errors"
	"fmt"
	"os"
)

func daemonProcessExited(pidPath string) (bool, error) {
	_, err := readDaemonPID(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, fmt.Errorf("daemon process identity is unsupported on this platform")
}

func daemonProcessExitedMarker(daemonPIDMarker) (bool, error) {
	return false, fmt.Errorf("daemon process identity is unsupported on this platform")
}

func forceStopDaemonProcess(string) error { return nil }

func forceStopDaemonMarker(daemonPIDMarker) error { return nil }

func cleanupStoppedDaemonArtifacts(_ string, pidPath string, expected daemonPIDMarker) error {
	return removeDaemonPID(pidPath, expected)
}
