package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestVaultStoresEncryptedCredential(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	masterPassword := []byte("initial master password")

	vault, err := store.Initialize(ctx, masterPassword)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	t.Cleanup(vault.Lock)

	want := []byte("database-password")
	if err := vault.PutCredential(ctx, "db-primary", "database password", want); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}

	var ciphertext []byte
	if err := store.db.QueryRow("SELECT ciphertext FROM credentials WHERE id = 'db-primary'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, want) {
		t.Fatal("credential ciphertext contains plaintext password")
	}

	got, err := vault.Credential(ctx, "db-primary")
	if err != nil {
		t.Fatalf("Credential() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Credential() = %q, want %q", got, want)
	}
}

func TestMasterPasswordChangeAndDataKeyRotationPreserveCredentials(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	oldPassword := []byte("old master password")
	newPassword := []byte("new master password")

	vault, err := store.Initialize(ctx, oldPassword)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := vault.PutCredential(ctx, "db-primary", "database password", []byte("first-secret")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	if err := vault.PutCredential(ctx, "ssh-primary", "SSH password", []byte("second-secret")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	vault.Lock()

	if err := store.ChangeMasterPassword(ctx, oldPassword, newPassword); err != nil {
		t.Fatalf("ChangeMasterPassword() error = %v", err)
	}
	if _, err := store.Unlock(ctx, oldPassword); !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("Unlock() with old password error = %v, want ErrUnlockFailed", err)
	}

	if err := store.RotateDataKey(ctx, newPassword); err != nil {
		t.Fatalf("RotateDataKey() error = %v", err)
	}

	reopened, err := store.Unlock(ctx, newPassword)
	if err != nil {
		t.Fatalf("Unlock() with new password error = %v", err)
	}
	t.Cleanup(reopened.Lock)
	for id, want := range map[string]string{
		"db-primary":  "first-secret",
		"ssh-primary": "second-secret",
	} {
		got, err := reopened.Credential(ctx, id)
		if err != nil {
			t.Fatalf("Credential(%q) error = %v", id, err)
		}
		if string(got) != want {
			t.Errorf("Credential(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestVaultLockClearsAccess(t *testing.T) {
	store := openTestStore(t)
	vault, err := store.Initialize(context.Background(), []byte("master password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	vault.Lock()

	if err := vault.PutCredential(context.Background(), "db-primary", "database password", []byte("secret")); !errors.Is(err, ErrLocked) {
		t.Fatalf("PutCredential() after Lock() error = %v, want ErrLocked", err)
	}
}

func TestDataKeyRotationRollsBackWhenCredentialCannotDecrypt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	masterPassword := []byte("master password")
	vault, err := store.Initialize(ctx, masterPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.PutCredential(ctx, "first", "first credential", []byte("first-secret")); err != nil {
		t.Fatal(err)
	}
	if err := vault.PutCredential(ctx, "second", "second credential", []byte("second-secret")); err != nil {
		t.Fatal(err)
	}
	vault.Lock()

	var beforeEnvelope []byte
	if err := store.db.QueryRow("SELECT ciphertext FROM key_envelopes WHERE id = 1").Scan(&beforeEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE credentials SET ciphertext = X'00' WHERE id = 'second'"); err != nil {
		t.Fatal(err)
	}

	if err := store.RotateDataKey(ctx, masterPassword); err == nil {
		t.Fatal("RotateDataKey() succeeded with a corrupt credential")
	}

	var afterEnvelope []byte
	if err := store.db.QueryRow("SELECT ciphertext FROM key_envelopes WHERE id = 1").Scan(&afterEnvelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterEnvelope, beforeEnvelope) {
		t.Fatal("data key envelope changed after failed rotation")
	}

	reopened, err := store.Unlock(ctx, masterPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Lock)
	credential, err := reopened.Credential(ctx, "first")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(credential), "first-secret"; got != want {
		t.Errorf("first credential = %q, want %q", got, want)
	}
}
