package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestKnownHostPinsInitialFingerprintAndRejectsUnexpectedChanges(t *testing.T) {
	t.Parallel()

	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if err := store.PinInitialHostKey(context.Background(), "192.0.2.10", 22, "SHA256:first"); err != nil {
		t.Fatalf("PinInitialHostKey() error = %v", err)
	}
	if err := store.PinInitialHostKey(context.Background(), "192.0.2.10", 22, "SHA256:first"); err != nil {
		t.Fatalf("same fingerprint pin error = %v", err)
	}
	if err := store.PinInitialHostKey(context.Background(), "192.0.2.10", 22, "SHA256:changed"); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("changed fingerprint pin error = %v, want ErrHostKeyMismatch", err)
	}

	fingerprint, err := store.HostKeyFingerprint(context.Background(), "192.0.2.10", 22)
	if err != nil || fingerprint != "SHA256:first" {
		t.Fatalf("HostKeyFingerprint() = %q, %v", fingerprint, err)
	}
	if err := store.ReplaceHostKey(context.Background(), "192.0.2.10", 22, "SHA256:changed"); err != nil {
		t.Fatalf("ReplaceHostKey() error = %v", err)
	}
}
