//go:build linux || darwin

package instance

import (
	"errors"
	"syscall"

	"os"
)

var errPlatformLockBusy = errors.New("instance lock is held by another process")

func platformLock(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errPlatformLockBusy
		}
		return err
	}
	return nil
}

func platformUnlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
