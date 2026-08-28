//go:build !darwin && !linux && !windows

package instance

import (
	"errors"
	"os"
)

var errPlatformLockBusy = errors.New("instance lock is held by another process")

func platformLock(*os.File) error {
	return errors.New("instance locks are unsupported on this platform")
}

func platformUnlock(*os.File) error { return nil }
