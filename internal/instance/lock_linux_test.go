package instance

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireAllowsOnlyOneLiveOwnerAndReleasesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}

	if _, err := Acquire(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Acquire(second) error = %v, want ErrAlreadyRunning", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}

	second, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire(after close) error = %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}
