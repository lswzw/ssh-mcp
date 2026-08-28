package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"ssh-mcp/internal/secret"
)

type Vault struct {
	store   *Store
	mu      sync.Mutex
	dataKey []byte
}

func (s *Store) Initialize(ctx context.Context, masterPassword []byte) (*Vault, error) {
	envelope, dataKey, err := secret.NewEnvelope(masterPassword)
	if err != nil {
		return nil, ErrUnlockFailed
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO key_envelopes (id, version, salt, nonce, ciphertext, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)`,
		envelope.Version, envelope.Salt, envelope.Nonce, envelope.Ciphertext, nowUnix(), nowUnix())
	if err != nil {
		secret.Zero(dataKey)
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrAlreadyInitialized
		}
		return nil, fmt.Errorf("save key envelope: %w", err)
	}

	return &Vault{store: s, dataKey: dataKey}, nil
}

func (s *Store) Unlock(ctx context.Context, masterPassword []byte) (*Vault, error) {
	envelope, err := s.loadEnvelope(ctx)
	if err != nil {
		return nil, err
	}

	dataKey, err := secret.Unlock(masterPassword, envelope)
	if err != nil {
		return nil, ErrUnlockFailed
	}
	return &Vault{store: s, dataKey: dataKey}, nil
}

func (s *Store) ChangeMasterPassword(ctx context.Context, oldMasterPassword, newMasterPassword []byte) error {
	envelope, err := s.loadEnvelope(ctx)
	if err != nil {
		return err
	}

	rewrapped, err := secret.Rewrap(oldMasterPassword, newMasterPassword, envelope)
	if err != nil {
		return ErrUnlockFailed
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE key_envelopes
		SET version = ?, salt = ?, nonce = ?, ciphertext = ?, updated_at = ?
		WHERE id = 1`, rewrapped.Version, rewrapped.Salt, rewrapped.Nonce, rewrapped.Ciphertext, nowUnix())
	if err != nil {
		return fmt.Errorf("update key envelope: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return ErrUninitialized
	}
	return nil
}

func (s *Store) RotateDataKey(ctx context.Context, masterPassword []byte) error {
	vault, err := s.Unlock(ctx, masterPassword)
	if err != nil {
		return err
	}
	defer vault.Lock()

	newEnvelope, newDataKey, err := secret.NewEnvelope(masterPassword)
	if err != nil {
		return ErrUnlockFailed
	}
	defer secret.Zero(newDataKey)

	return vault.withDataKey(func(oldDataKey []byte) error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin data key rotation: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		rows, err := tx.QueryContext(ctx, "SELECT id, ciphertext FROM credentials")
		if err != nil {
			return fmt.Errorf("list credentials for rotation: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var id string
			var ciphertext []byte
			if err := rows.Scan(&id, &ciphertext); err != nil {
				return fmt.Errorf("read credential for rotation: %w", err)
			}
			plaintext, err := secret.Decrypt(oldDataKey, ciphertext, credentialAAD(id))
			if err != nil {
				return fmt.Errorf("decrypt credential for rotation: %w", err)
			}
			reencrypted, err := secret.Encrypt(newDataKey, plaintext, credentialAAD(id))
			secret.Zero(plaintext)
			if err != nil {
				return fmt.Errorf("encrypt credential for rotation: %w", err)
			}
			if _, err := tx.ExecContext(ctx, "UPDATE credentials SET ciphertext = ?, updated_at = ? WHERE id = ?", reencrypted, nowUnix(), id); err != nil {
				return fmt.Errorf("update credential for rotation: %w", err)
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate credentials for rotation: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE key_envelopes
			SET version = ?, salt = ?, nonce = ?, ciphertext = ?, updated_at = ?
			WHERE id = 1`, newEnvelope.Version, newEnvelope.Salt, newEnvelope.Nonce, newEnvelope.Ciphertext, nowUnix()); err != nil {
			return fmt.Errorf("update envelope for rotation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit data key rotation: %w", err)
		}
		return nil
	})
}

func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	secret.Zero(v.dataKey)
	v.dataKey = nil
}

func (v *Vault) PutCredential(ctx context.Context, id, purpose string, plaintext []byte) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(purpose) == "" {
		return ErrInvalidCredential
	}

	return v.withDataKey(func(dataKey []byte) error {
		tx, err := v.store.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin credential save: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		var owned bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM credential_owners WHERE credential_id = ?)", id).Scan(&owned); err != nil {
			return fmt.Errorf("check credential owner: %w", err)
		}
		if owned {
			return ErrCredentialOwnerConflict
		}
		ciphertext, err := secret.Encrypt(dataKey, plaintext, credentialAAD(id))
		if err != nil {
			return fmt.Errorf("encrypt credential: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO credentials (id, purpose, ciphertext, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				purpose = excluded.purpose,
				ciphertext = excluded.ciphertext,
				updated_at = excluded.updated_at`, id, purpose, ciphertext, nowUnix(), nowUnix())
		if err != nil {
			return fmt.Errorf("save credential: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit credential save: %w", err)
		}
		return nil
	})
}

func (v *Vault) Credential(ctx context.Context, id string) ([]byte, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrInvalidCredential
	}

	var plaintext []byte
	err := v.withDataKey(func(dataKey []byte) error {
		var ciphertext []byte
		err := v.store.db.QueryRowContext(ctx, "SELECT ciphertext FROM credentials WHERE id = ?", id).Scan(&ciphertext)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCredentialNotFound
		}
		if err != nil {
			return fmt.Errorf("load credential: %w", err)
		}
		plaintext, err = secret.Decrypt(dataKey, ciphertext, credentialAAD(id))
		if err != nil {
			return fmt.Errorf("decrypt credential: %w", err)
		}
		return nil
	})
	if err != nil {
		secret.Zero(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (v *Vault) withDataKey(action func([]byte) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.dataKey) == 0 {
		return ErrLocked
	}
	return action(v.dataKey)
}

func (s *Store) loadEnvelope(ctx context.Context) (secret.Envelope, error) {
	var envelope secret.Envelope
	err := s.db.QueryRowContext(ctx, `
		SELECT version, salt, nonce, ciphertext
		FROM key_envelopes
		WHERE id = 1`).Scan(&envelope.Version, &envelope.Salt, &envelope.Nonce, &envelope.Ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return secret.Envelope{}, ErrUninitialized
	}
	if err != nil {
		return secret.Envelope{}, fmt.Errorf("load key envelope: %w", err)
	}
	return envelope, nil
}

func credentialAAD(id string) []byte {
	return []byte("ssh-mcp:credential:" + id)
}
