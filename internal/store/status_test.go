package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestTUILanguagePersistence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Default should be empty before any set
	lang, err := store.GetTUILanguage(ctx)
	if err != nil {
		t.Fatalf("GetTUILanguage() error = %v", err)
	}
	if lang != "" {
		t.Fatalf("initial language = %q, want empty", lang)
	}

	// Set to en
	if err := store.SetTUILanguage(ctx, "en"); err != nil {
		t.Fatalf("SetTUILanguage(en) error = %v", err)
	}
	lang, err = store.GetTUILanguage(ctx)
	if err != nil {
		t.Fatalf("GetTUILanguage() error = %v", err)
	}
	if lang != "en" {
		t.Fatalf("got language = %q, want en", lang)
	}

	// Update to zh
	if err := store.SetTUILanguage(ctx, "zh"); err != nil {
		t.Fatalf("SetTUILanguage(zh) error = %v", err)
	}
	lang, err = store.GetTUILanguage(ctx)
	if err != nil {
		t.Fatalf("GetTUILanguage() error = %v", err)
	}
	if lang != "zh" {
		t.Fatalf("got language = %q, want zh", lang)
	}

	// Reject invalid language
	if err := store.SetTUILanguage(ctx, "fr"); err == nil {
		t.Fatal("expected error for unsupported language fr, got nil")
	}
}
