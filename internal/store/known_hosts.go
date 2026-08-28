package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

func (s *Store) PinInitialHostKey(ctx context.Context, host string, port int, fingerprint string) error {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 || strings.TrimSpace(fingerprint) == "" {
		return ErrInvalidTarget
	}
	var current string
	err = s.db.QueryRowContext(ctx, "SELECT fingerprint FROM known_hosts WHERE host = ? AND port = ?", canonical, port).Scan(&current)
	if err == nil {
		if current == fingerprint {
			return nil
		}
		return ErrHostKeyMismatch
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("load SSH host key: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO known_hosts (host, port, fingerprint, confirmed_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, canonical, port, fingerprint, nowUnix(), nowUnix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

// ReplaceHostKey is reserved for an explicit local TUI confirmation after the
// transport has refused a changed host key.
func (s *Store) ReplaceHostKey(ctx context.Context, host string, port int, fingerprint string) error {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 || strings.TrimSpace(fingerprint) == "" {
		return ErrInvalidTarget
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE known_hosts
		SET fingerprint = ?, confirmed_at = ?, updated_at = ?
		WHERE host = ? AND port = ?`, fingerprint, nowUnix(), nowUnix(), canonical, port)
	if err != nil {
		return fmt.Errorf("replace SSH host key: %w", err)
	}
	return expectHostKey(result)
}

func (s *Store) HostKeyFingerprint(ctx context.Context, host string, port int) (string, error) {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 {
		return "", ErrInvalidTarget
	}
	var fingerprint string
	err = s.db.QueryRowContext(ctx, "SELECT fingerprint FROM known_hosts WHERE host = ? AND port = ?", canonical, port).Scan(&fingerprint)
	if err == sql.ErrNoRows {
		return "", ErrHostKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("load SSH host key: %w", err)
	}
	return fingerprint, nil
}

// upsertValidatedHostKeyTx 写入候选验证过的主机身份，并报告既有指纹是否发生变化。
func upsertValidatedHostKeyTx(ctx context.Context, tx *sql.Tx, host string, port int, fingerprint string) (bool, error) {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 || strings.TrimSpace(fingerprint) == "" {
		return false, ErrInvalidTarget
	}
	var current string
	err = tx.QueryRowContext(ctx, "SELECT fingerprint FROM known_hosts WHERE host = ? AND port = ?", canonical, port).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("读取已登记 SSH 主机身份失败：%w", err)
	}
	exists := err == nil
	_, err = tx.ExecContext(ctx, `
		INSERT INTO known_hosts (host, port, fingerprint, confirmed_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host, port) DO UPDATE SET
			fingerprint = excluded.fingerprint,
			confirmed_at = excluded.confirmed_at,
			updated_at = excluded.updated_at`, canonical, port, fingerprint, nowUnix(), nowUnix())
	if err != nil {
		return false, mapConstraintError(err)
	}
	return exists && current != fingerprint, nil
}

func expectHostKey(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check SSH host key replacement: %w", err)
	}
	if affected != 1 {
		return ErrHostKeyNotFound
	}
	return nil
}
