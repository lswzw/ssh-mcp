package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type SessionState string

const (
	SessionUnlocked SessionState = "unlocked"
	SessionLocked   SessionState = "locked"
)

type SessionRecord struct {
	ID             string
	State          SessionState
	CreatedAt      time.Time
	LastActivityAt time.Time
	ExpiresAt      time.Time
}

func (s *Store) CreateSession(ctx context.Context, session SessionRecord) error {
	if strings.TrimSpace(session.ID) == "" || (session.State != SessionUnlocked && session.State != SessionLocked) ||
		session.CreatedAt.IsZero() || session.LastActivityAt.IsZero() || session.ExpiresAt.IsZero() {
		return ErrInvalidTarget
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, state, created_at, last_activity_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`, session.ID, session.State, session.CreatedAt.UTC().Unix(), session.LastActivityAt.UTC().Unix(), session.ExpiresAt.UTC().Unix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

func (s *Store) SetSessionState(ctx context.Context, id string, state SessionState, lastActivity, expiresAt time.Time) error {
	if strings.TrimSpace(id) == "" || (state != SessionUnlocked && state != SessionLocked) || lastActivity.IsZero() || expiresAt.IsZero() {
		return ErrInvalidTarget
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET state = ?, last_activity_at = ?, expires_at = ? WHERE id = ?`,
		state, lastActivity.UTC().Unix(), expiresAt.UTC().Unix(), id)
	if err != nil {
		return fmt.Errorf("update session state: %w", err)
	}
	return expectTarget(result)
}
