package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupAndRestore(t *testing.T) {
	root := t.TempDir()
	store, err := Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	masterPassword := []byte("backup master password")
	vault, err := store.Initialize(ctx, masterPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Lock)
	if err := vault.PutCredential(ctx, "db-primary", "database password", []byte("backup-secret")); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(root, "backup.sshmcp")
	if err := store.CreateBackup(ctx, masterPassword, backupPath); err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup, []byte("backup-secret")) {
		t.Fatal("encrypted backup contains plaintext credential")
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("backup is not a regular file: %v", info.Mode())
	}

	restoredPath := filepath.Join(root, "restored.db")
	if err := RestoreBackup(ctx, masterPassword, backupPath, restoredPath); err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	restored, err := Open(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	restoredVault, err := restored.Unlock(ctx, masterPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoredVault.Lock)

	credential, err := restoredVault.Credential(ctx, "db-primary")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(credential), "backup-secret"; got != want {
		t.Errorf("restored credential = %q, want %q", got, want)
	}
}

func TestRestoreBackupRejectsWrongMasterPassword(t *testing.T) {
	root := t.TempDir()
	store, err := Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	masterPassword := []byte("correct password")
	if _, err := store.Initialize(ctx, masterPassword); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(root, "backup.sshmcp")
	if err := store.CreateBackup(ctx, masterPassword, backupPath); err != nil {
		t.Fatal(err)
	}

	err = RestoreBackup(ctx, []byte("wrong password"), backupPath, filepath.Join(root, "restored.db"))
	if !errors.Is(err, ErrBackupUnlockFailed) {
		t.Fatalf("RestoreBackup() error = %v, want ErrBackupUnlockFailed", err)
	}
}
