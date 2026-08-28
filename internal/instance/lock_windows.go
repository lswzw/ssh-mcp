//go:build windows

package instance

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errPlatformLockBusy = errors.New("instance lock is held by another process")

// Lock one byte so the lock remains valid even when the marker file is empty.
// LockFileEx is process-safe and is released explicitly before closing the
// handle (closing also releases it as a final safeguard).
func platformLock(file *os.File) error {
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{},
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return errPlatformLockBusy
		}
		return err
	}
	return nil
}

func platformUnlock(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
