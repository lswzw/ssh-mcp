//go:build !darwin && !linux && !windows

package bridge

import "errors"

var errProcessIdentityUnsupported = errors.New("process identity is unsupported on this platform")

func platformProcessWorkingDirectory(int) string { return "" }

func platformProcessStartTime(int) (uint64, error) {
	return 0, errProcessIdentityUnsupported
}
