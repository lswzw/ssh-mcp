package secret

import (
	"bytes"
	"testing"
)

func TestNewEnvelopeRoundTrip(t *testing.T) {
	masterPassword := []byte("correct horse battery staple")
	envelope, dataKey, err := NewEnvelope(masterPassword)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	t.Cleanup(func() { Zero(dataKey) })

	unlocked, err := Unlock(masterPassword, envelope)
	if err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	t.Cleanup(func() { Zero(unlocked) })

	if !bytes.Equal(unlocked, dataKey) {
		t.Fatal("Unlock() returned a different data key")
	}
}

func TestRewrapEnvelopeRejectsOldMasterPassword(t *testing.T) {
	oldPassword := []byte("old master password")
	newPassword := []byte("new master password")
	envelope, dataKey, err := NewEnvelope(oldPassword)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	t.Cleanup(func() { Zero(dataKey) })

	rewrapped, err := Rewrap(oldPassword, newPassword, envelope)
	if err != nil {
		t.Fatalf("Rewrap() error = %v", err)
	}

	if _, err := Unlock(oldPassword, rewrapped); err == nil {
		t.Fatal("Unlock() with old password succeeded after rewrap")
	}

	unlocked, err := Unlock(newPassword, rewrapped)
	if err != nil {
		t.Fatalf("Unlock() with new password error = %v", err)
	}
	t.Cleanup(func() { Zero(unlocked) })
	if !bytes.Equal(unlocked, dataKey) {
		t.Fatal("rewrap changed the data key")
	}
}

func TestDecryptRejectsWrongAssociatedData(t *testing.T) {
	_, dataKey, err := NewEnvelope([]byte("master password"))
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	t.Cleanup(func() { Zero(dataKey) })

	ciphertext, err := Encrypt(dataKey, []byte("database password"), []byte("credential:primary-db"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := Decrypt(dataKey, ciphertext, []byte("credential:other-db")); err == nil {
		t.Fatal("Decrypt() with different associated data succeeded")
	}
}
