package session

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ssh-mcp/internal/store"
)

func TestManagerInitializesUnlocksAndLocksVault(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()

	manager := NewManager(credentialStore)
	created, err := manager.Unlock(context.Background(), []byte("first-master-password"))
	if err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	if !created || !manager.IsUnlocked() {
		t.Fatalf("initial unlock state = created:%v unlocked:%v, want true:true", created, manager.IsUnlocked())
	}
	if _, err := manager.Vault(); err != nil {
		t.Fatalf("Vault() error = %v", err)
	}

	manager.Lock()
	if manager.IsUnlocked() {
		t.Fatal("manager remains unlocked after Lock()")
	}
	if _, err := manager.Vault(); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("Vault() after lock error = %v, want ErrLocked", err)
	}

	created, err = manager.Unlock(context.Background(), []byte("first-master-password"))
	if err != nil {
		t.Fatalf("second Unlock() error = %v", err)
	}
	if created {
		t.Fatal("second unlock unexpectedly initialized the store")
	}
	manager.Lock()

	_, err = manager.Unlock(context.Background(), []byte("wrong-master-password"))
	if !errors.Is(err, store.ErrUnlockFailed) {
		t.Fatalf("wrong master password error = %v, want ErrUnlockFailed", err)
	}
}

func TestManagerKeepsVaultUnlockedUntilExplicitLock(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()

	manager := NewManager(credentialStore)
	if _, err := manager.Unlock(context.Background(), []byte("first-master-password")); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	manager.TouchRemoteActivity()
	time.Sleep(100 * time.Millisecond)
	if !manager.IsUnlocked() {
		t.Fatal("manager locked without an explicit lock or daemon shutdown")
	}
}

func TestManagerBacksOffFailedUnlocksAndResetsAfterSuccess(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	now := time.Date(2026, time.July, 24, 10, 0, 0, 0, time.UTC)
	manager := NewManagerWithOptions(credentialStore, Options{Now: func() time.Time { return now }})
	if _, err := manager.Unlock(context.Background(), []byte("correct-password")); err != nil {
		t.Fatalf("initial Unlock() error = %v", err)
	}
	manager.Lock()
	if _, err := manager.Unlock(context.Background(), []byte("wrong-password")); !errors.Is(err, store.ErrUnlockFailed) {
		t.Fatalf("wrong Unlock() error = %v, want ErrUnlockFailed", err)
	}
	if _, err := manager.Unlock(context.Background(), []byte("correct-password")); !errors.Is(err, ErrUnlockRateLimited) {
		t.Fatalf("backoff Unlock() error = %v, want ErrUnlockRateLimited", err)
	}
	now = now.Add(initialUnlockBackoff)
	if _, err := manager.Unlock(context.Background(), []byte("correct-password")); err != nil {
		t.Fatalf("unlock after backoff error = %v", err)
	}
	manager.Lock()
	if _, err := manager.Unlock(context.Background(), []byte("wrong-password")); !errors.Is(err, store.ErrUnlockFailed) {
		t.Fatalf("wrong Unlock after reset error = %v, want ErrUnlockFailed", err)
	}
	now = now.Add(initialUnlockBackoff)
	if _, err := manager.Unlock(context.Background(), []byte("correct-password")); err != nil {
		t.Fatalf("unlock after reset backoff error = %v", err)
	}
}
