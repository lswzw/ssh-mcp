package store

import (
	"context"
	"fmt"
)

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	var initialized bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM key_envelopes WHERE id = 1)").Scan(&initialized); err != nil {
		return false, fmt.Errorf("check credential store initialization: %w", err)
	}
	return initialized, nil
}
