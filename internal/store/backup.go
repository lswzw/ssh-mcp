package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ssh-mcp/internal/paths"
	"ssh-mcp/internal/secret"

	_ "modernc.org/sqlite"
)

const (
	backupFormat  = "ssh-mcp-backup"
	backupVersion = 1
)

type backupDocument struct {
	Format     string          `json:"format"`
	Version    int             `json:"version"`
	Envelope   secret.Envelope `json:"envelope"`
	Ciphertext []byte          `json:"ciphertext"`
}

func (s *Store) CreateBackup(ctx context.Context, masterPassword []byte, destination string) error {
	vault, err := s.Unlock(ctx, masterPassword)
	if err != nil {
		return ErrBackupUnlockFailed
	}
	vault.Lock()

	snapshot, err := s.snapshot(ctx, filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(snapshot) }()

	plain, err := os.ReadFile(snapshot)
	if err != nil {
		return fmt.Errorf("read backup snapshot: %w", err)
	}
	defer secret.Zero(plain)

	envelope, backupKey, err := secret.NewEnvelope(masterPassword)
	if err != nil {
		return ErrBackupUnlockFailed
	}
	defer secret.Zero(backupKey)
	ciphertext, err := secret.Encrypt(backupKey, plain, []byte("ssh-mcp:backup:v1"))
	if err != nil {
		return fmt.Errorf("encrypt backup: %w", err)
	}

	document, err := json.Marshal(backupDocument{
		Format:     backupFormat,
		Version:    backupVersion,
		Envelope:   envelope,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return fmt.Errorf("encode backup: %w", err)
	}
	return writeFile(destination, document)
}

func RestoreBackup(ctx context.Context, masterPassword []byte, source, destination string) error {
	if err := rejectSymlink(source); err != nil {
		return err
	}
	encoded, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}

	var document backupDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		return ErrInvalidBackup
	}
	if document.Format != backupFormat || document.Version != backupVersion {
		return ErrInvalidBackup
	}
	backupKey, err := secret.Unlock(masterPassword, document.Envelope)
	if err != nil {
		return ErrBackupUnlockFailed
	}
	defer secret.Zero(backupKey)
	plain, err := secret.Decrypt(backupKey, document.Ciphertext, []byte("ssh-mcp:backup:v1"))
	if err != nil {
		return ErrInvalidBackup
	}
	defer secret.Zero(plain)

	if err := paths.EnsureDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("create restore directory: %w", err)
	}
	temporary, err := paths.CreateTemp(filepath.Dir(destination), ".ssh-mcp-restore-*")
	if err != nil {
		return fmt.Errorf("create restore file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(plain); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write restore file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync restore file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close restore file: %w", err)
	}
	if err := validateSnapshot(ctx, temporaryPath); err != nil {
		return err
	}
	if err := rejectSymlink(destination); err != nil {
		return err
	}
	if err := paths.ReplaceFile(temporaryPath, destination); err != nil {
		return fmt.Errorf("replace restored database: %w", err)
	}
	if err := paths.SyncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sync restore directory: %w", err)
	}
	if err := paths.EnsureRegularFile(destination); err != nil {
		return fmt.Errorf("verify restored database: %w", err)
	}
	return nil
}

func (s *Store) snapshot(ctx context.Context, directory string) (string, error) {
	if err := paths.EnsureDirectory(directory); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	temporary, err := paths.CreateTemp(directory, ".ssh-mcp-snapshot-*")
	if err != nil {
		return "", fmt.Errorf("create snapshot path: %w", err)
	}
	path := temporary.Name()
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close snapshot path: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("prepare snapshot path: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return "", fmt.Errorf("create sqlite snapshot: %w", err)
	}
	if err := paths.EnsureRegularFile(path); err != nil {
		return "", fmt.Errorf("verify snapshot: %w", err)
	}
	return path, nil
}

func validateSnapshot(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return ErrInvalidBackup
	}
	defer db.Close()

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil || count == 0 {
		return ErrInvalidBackup
	}
	return nil
}

func writeFile(path string, data []byte) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if err := paths.EnsureDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := paths.CreateTemp(filepath.Dir(path), ".ssh-mcp-write-*")
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write output file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	if err := paths.ReplaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("replace output file: %w", err)
	}
	if err := paths.SyncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	if err := paths.EnsureRegularFile(path); err != nil {
		return fmt.Errorf("verify output file: %w", err)
	}
	return nil
}
