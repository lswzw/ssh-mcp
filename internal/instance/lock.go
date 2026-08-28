// Package instance prevents multiple local ssh-mcp owners from using the
// same state database at once.
package instance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrAlreadyRunning = errors.New("ssh-mcp is already running")

var heldPaths = struct {
	sync.Mutex
	values map[string]bool
}{values: make(map[string]bool)}

type Lock struct {
	path string
	file *os.File
	mu   sync.Mutex
}

func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, errors.New("instance lock path is empty")
	}
	canonical, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve instance lock path: %w", err)
	}

	heldPaths.Lock()
	if heldPaths.values[canonical] {
		heldPaths.Unlock()
		return nil, ErrAlreadyRunning
	}
	heldPaths.values[canonical] = true
	heldPaths.Unlock()

	file, err := openAndLock(canonical)
	if err != nil {
		releaseHeldPath(canonical)
		return nil, err
	}
	return &Lock{path: canonical, file: file}, nil
}

func openAndLock(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("instance lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect instance lock: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	if err := platformLock(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errPlatformLockBusy) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("acquire instance lock: %w", err)
	}
	return file, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	file := l.file
	l.file = nil
	l.mu.Unlock()
	if file == nil {
		return nil
	}
	unlockErr := platformUnlock(file)
	closeErr := file.Close()
	releaseHeldPath(l.path)
	if unlockErr != nil {
		return fmt.Errorf("release instance lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close instance lock: %w", closeErr)
	}
	return nil
}

func releaseHeldPath(path string) {
	heldPaths.Lock()
	delete(heldPaths.values, path)
	heldPaths.Unlock()
}
