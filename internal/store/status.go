package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const metadataKeyTUILanguage = "tui_language"

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	var initialized bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM key_envelopes WHERE id = 1)").Scan(&initialized); err != nil {
		return false, fmt.Errorf("check credential store initialization: %w", err)
	}
	return initialized, nil
}

func (s *Store) GetTUILanguage(ctx context.Context) (string, error) {
	var lang []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = ?", metadataKeyTUILanguage).Scan(&lang)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read TUI language metadata: %w", err)
	}
	return string(lang), nil
}

func (s *Store) SetTUILanguage(ctx context.Context, lang string) error {
	lang = strings.TrimSpace(lang)
	if lang != "zh" && lang != "en" {
		return fmt.Errorf("unsupported language %q, must be zh or en", lang)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO metadata (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, metadataKeyTUILanguage, []byte(lang))
	if err != nil {
		return fmt.Errorf("write TUI language metadata: %w", err)
	}
	return nil
}

