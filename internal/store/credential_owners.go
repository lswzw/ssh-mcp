package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"ssh-mcp/internal/secret"
)

const (
	credentialOwnerProtocolSSH      = "ssh"
	credentialOwnerProtocolDatabase = "database"
	credentialIdentitySSH           = "ssh"
	credentialIdentityRead          = "read"
	credentialIdentityWrite         = "write"
)

type credentialOwner struct {
	protocol   string
	targetHost string
	targetPort int
	identity   string
}

type targetCredentialReferenceKind int

const (
	targetCredentialReferenceSSH targetCredentialReferenceKind = iota
	targetCredentialReferenceDatabaseRead
	targetCredentialReferenceDatabaseWrite
)

type targetCredentialReference struct {
	kind         targetCredentialReferenceKind
	owner        credentialOwner
	credentialID string
}

func (v *Vault) PutSSHTargetCredential(ctx context.Context, target SSHTarget, plaintext []byte) (string, error) {
	owner, err := sshCredentialOwner(target)
	if err != nil {
		return "", err
	}
	return v.putOwnedCredential(ctx, owner, "ssh-password", plaintext)
}

func (v *Vault) PutDatabaseReadCredential(ctx context.Context, instance DatabaseInstance, plaintext []byte) (string, error) {
	owner, err := databaseCredentialOwner(instance, credentialIdentityRead)
	if err != nil {
		return "", ErrInvalidTarget
	}
	return v.putOwnedCredential(ctx, owner, "database-read-password", plaintext)
}

func (v *Vault) PutDatabaseWriteCredential(ctx context.Context, instance DatabaseInstance, plaintext []byte) (string, error) {
	owner, err := databaseCredentialOwner(instance, credentialIdentityWrite)
	if err != nil {
		return "", ErrInvalidTarget
	}
	return v.putOwnedCredential(ctx, owner, "database-write-password", plaintext)
}

func (v *Vault) putOwnedCredential(ctx context.Context, owner credentialOwner, purpose string, plaintext []byte) (string, error) {
	if !owner.valid() || strings.TrimSpace(purpose) == "" {
		return "", ErrInvalidCredential
	}

	var credentialID string
	err := v.withDataKey(func(dataKey []byte) error {
		tx, err := v.store.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin owned credential update: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		credentialID, err = putOwnedCredentialTx(ctx, tx, dataKey, owner, purpose, plaintext)
		if err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit owned credential update: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return credentialID, nil
}

func putOwnedCredentialTx(ctx context.Context, tx *sql.Tx, dataKey []byte, owner credentialOwner, purpose string, plaintext []byte) (string, error) {
	if !owner.valid() || strings.TrimSpace(purpose) == "" {
		return "", ErrInvalidCredential
	}

	credentialID, found, err := credentialIDForOwnerTx(ctx, tx, owner)
	if err != nil {
		return "", err
	}
	if !found {
		credentialID, err = newCredentialID()
		if err != nil {
			return "", fmt.Errorf("generate credential identifier: %w", err)
		}
	}

	ciphertext, err := secret.Encrypt(dataKey, plaintext, credentialAAD(credentialID))
	if err != nil {
		return "", fmt.Errorf("encrypt owned credential: %w", err)
	}

	if found {
		result, err := tx.ExecContext(ctx, `
			UPDATE credentials
			SET purpose = ?, ciphertext = ?, updated_at = ?
			WHERE id = ?`, purpose, ciphertext, nowUnix(), credentialID)
		if err != nil {
			return "", fmt.Errorf("update owned credential: %w", err)
		}
		if err := expectCredential(result); err != nil {
			return "", err
		}
		return credentialID, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credentials (id, purpose, ciphertext, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, credentialID, purpose, ciphertext, nowUnix(), nowUnix()); err != nil {
		return "", fmt.Errorf("insert owned credential: %w", err)
	}
	if err := insertCredentialOwnerTx(ctx, tx, credentialID, owner); err != nil {
		return "", err
	}
	return credentialID, nil
}

// rotateOwnedCredentialTx 为已验证的配置变更创建新的凭据记录。目标引用切换后，
// 调用方必须在同一事务中删除返回的旧记录，避免轮换历史继续可解密。
func rotateOwnedCredentialTx(ctx context.Context, tx *sql.Tx, dataKey []byte, owner credentialOwner, purpose string, plaintext []byte) (string, string, error) {
	if !owner.valid() || strings.TrimSpace(purpose) == "" {
		return "", "", ErrInvalidCredential
	}

	oldID, found, err := credentialIDForOwnerTx(ctx, tx, owner)
	if err != nil {
		return "", "", err
	}
	credentialID, err := newCredentialID()
	if err != nil {
		return "", "", fmt.Errorf("generate rotated credential identifier: %w", err)
	}
	ciphertext, err := secret.Encrypt(dataKey, plaintext, credentialAAD(credentialID))
	if err != nil {
		return "", "", fmt.Errorf("encrypt rotated credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credentials (id, purpose, ciphertext, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`, credentialID, purpose, ciphertext, nowUnix(), nowUnix()); err != nil {
		return "", "", fmt.Errorf("insert rotated credential: %w", err)
	}

	if !found {
		if err := insertCredentialOwnerTx(ctx, tx, credentialID, owner); err != nil {
			return "", "", err
		}
		return credentialID, "", nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE credential_owners
		SET credential_id = ?
		WHERE credential_id = ?`, credentialID, oldID)
	if err != nil {
		return "", "", fmt.Errorf("move credential owner during rotation: %w", err)
	}
	if err := expectCredential(result); err != nil {
		return "", "", err
	}
	return credentialID, oldID, nil
}

func (v *Vault) MigrateTargetCredentialOwners(ctx context.Context) error {
	err := v.withDataKey(func(dataKey []byte) error {
		return v.migrateTargetCredentialOwners(ctx, dataKey)
	})
	if err == nil || errors.Is(err, ErrLocked) {
		return err
	}
	return ErrCredentialMigrationFailed
}

func (v *Vault) migrateTargetCredentialOwners(ctx context.Context, dataKey []byte) error {
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin credential migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	references, err := loadTargetCredentialReferencesTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, reference := range references {
		boundOwner, bound, err := credentialOwnerForIDTx(ctx, tx, reference.credentialID)
		if err != nil {
			return err
		}
		if bound {
			if boundOwner != reference.owner {
				return ErrCredentialOwnerConflict
			}
			continue
		}
		if _, ownerBound, err := credentialIDForOwnerTx(ctx, tx, reference.owner); err != nil {
			return err
		} else if ownerBound {
			return ErrCredentialOwnerConflict
		}

		purpose, ciphertext, err := credentialRecordTx(ctx, tx, reference.credentialID)
		if err != nil {
			return err
		}
		plaintext, err := secret.Decrypt(dataKey, ciphertext, credentialAAD(reference.credentialID))
		if err != nil {
			return fmt.Errorf("decrypt legacy credential: %w", err)
		}
		newID, err := newCredentialID()
		if err != nil {
			secret.Zero(plaintext)
			return fmt.Errorf("generate migrated credential identifier: %w", err)
		}
		reencrypted, err := secret.Encrypt(dataKey, plaintext, credentialAAD(newID))
		secret.Zero(plaintext)
		if err != nil {
			return fmt.Errorf("encrypt migrated credential: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO credentials (id, purpose, ciphertext, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)`, newID, purpose, reencrypted, nowUnix(), nowUnix()); err != nil {
			return fmt.Errorf("insert migrated credential: %w", err)
		}
		if err := insertCredentialOwnerTx(ctx, tx, newID, reference.owner); err != nil {
			return err
		}
		if err := updateTargetCredentialReferenceTx(ctx, tx, reference, newID); err != nil {
			return err
		}
	}
	if err := v.store.commitTargetCredentialMigration(tx); err != nil {
		return fmt.Errorf("commit credential migration: %w", err)
	}
	return nil
}

func (s *Store) commitTargetCredentialMigration(tx *sql.Tx) error {
	if s.credentialMigrationCommit != nil {
		return s.credentialMigrationCommit(tx)
	}
	return tx.Commit()
}

func loadTargetCredentialReferencesTx(ctx context.Context, tx *sql.Tx) ([]targetCredentialReference, error) {
	references := make([]targetCredentialReference, 0)
	if err := appendSSHTargetCredentialReferences(ctx, tx, &references); err != nil {
		return nil, err
	}
	if err := appendDatabaseTargetCredentialReferences(ctx, tx, credentialIdentityRead, targetCredentialReferenceDatabaseRead, &references); err != nil {
		return nil, err
	}
	if err := appendDatabaseTargetCredentialReferences(ctx, tx, credentialIdentityWrite, targetCredentialReferenceDatabaseWrite, &references); err != nil {
		return nil, err
	}
	return references, nil
}

func appendSSHTargetCredentialReferences(ctx context.Context, tx *sql.Tx, references *[]targetCredentialReference) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT ip, credential_id
		FROM ssh_targets
		WHERE connection_mode = 'direct' AND credential_id IS NOT NULL AND credential_id <> ''
		ORDER BY ip`)
	if err != nil {
		return fmt.Errorf("list SSH credential references: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host, credentialID string
		if err := rows.Scan(&host, &credentialID); err != nil {
			return fmt.Errorf("read SSH credential reference: %w", err)
		}
		owner, err := sshCredentialOwner(SSHTarget{IP: host, Mode: SSHDirect, LoginUsername: "legacy"})
		if err != nil {
			return err
		}
		*references = append(*references, targetCredentialReference{
			kind: targetCredentialReferenceSSH, owner: owner, credentialID: credentialID,
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate SSH credential references: %w", err)
	}
	return nil
}

func appendDatabaseTargetCredentialReferences(ctx context.Context, tx *sql.Tx, identity string, kind targetCredentialReferenceKind, references *[]targetCredentialReference) error {
	column := "read_credential_id"
	if identity == credentialIdentityWrite {
		column = "write_credential_id"
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT host, port, `+column+`
		FROM database_instances
		WHERE `+column+` IS NOT NULL AND `+column+` <> ''
		ORDER BY host, port`)
	if err != nil {
		return fmt.Errorf("list database credential references: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host, credentialID string
		var port int
		if err := rows.Scan(&host, &port, &credentialID); err != nil {
			return fmt.Errorf("read database credential reference: %w", err)
		}
		owner, err := databaseCredentialOwner(DatabaseInstance{Host: host, Port: port, ReadUsername: "legacy", WriteUsername: "legacy"}, identity)
		if err != nil {
			return err
		}
		*references = append(*references, targetCredentialReference{
			kind: kind, owner: owner, credentialID: credentialID,
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database credential references: %w", err)
	}
	return nil
}

func updateTargetCredentialReferenceTx(ctx context.Context, tx *sql.Tx, reference targetCredentialReference, credentialID string) error {
	var result sql.Result
	var err error
	switch reference.kind {
	case targetCredentialReferenceSSH:
		result, err = tx.ExecContext(ctx, `
			UPDATE ssh_targets
			SET credential_id = ?, revision = revision + 1, updated_at = ?
			WHERE ip = ? AND connection_mode = 'direct' AND credential_id = ?`,
			credentialID, nowUnix(), reference.owner.targetHost, reference.credentialID)
	case targetCredentialReferenceDatabaseRead:
		result, err = tx.ExecContext(ctx, `
			UPDATE database_instances
			SET read_credential_id = ?, revision = revision + 1, updated_at = ?
			WHERE host = ? AND port = ? AND read_credential_id = ?`,
			credentialID, nowUnix(), reference.owner.targetHost, reference.owner.targetPort, reference.credentialID)
	case targetCredentialReferenceDatabaseWrite:
		result, err = tx.ExecContext(ctx, `
			UPDATE database_instances
			SET write_credential_id = ?, revision = revision + 1, updated_at = ?
			WHERE host = ? AND port = ? AND write_credential_id = ?`,
			credentialID, nowUnix(), reference.owner.targetHost, reference.owner.targetPort, reference.credentialID)
	default:
		return ErrCredentialMigrationFailed
	}
	if err != nil {
		return fmt.Errorf("update migrated credential reference: %w", err)
	}
	return expectCredential(result)
}

func ensureCredentialOwnerTx(ctx context.Context, tx *sql.Tx, credentialID string, owner credentialOwner) error {
	if strings.TrimSpace(credentialID) == "" || !owner.valid() {
		return ErrInvalidCredential
	}
	boundOwner, bound, err := credentialOwnerForIDTx(ctx, tx, credentialID)
	if err != nil {
		return err
	}
	if bound {
		if boundOwner != owner {
			return ErrCredentialOwnerConflict
		}
		return nil
	}
	if _, ownerBound, err := credentialIDForOwnerTx(ctx, tx, owner); err != nil {
		return err
	} else if ownerBound {
		return ErrCredentialOwnerConflict
	}
	if _, _, err := credentialRecordTx(ctx, tx, credentialID); err != nil {
		return err
	}
	return insertCredentialOwnerTx(ctx, tx, credentialID, owner)
}

func credentialOwnerForIDTx(ctx context.Context, tx *sql.Tx, credentialID string) (credentialOwner, bool, error) {
	var owner credentialOwner
	err := tx.QueryRowContext(ctx, `
		SELECT protocol, target_host, target_port, identity
		FROM credential_owners WHERE credential_id = ?`, credentialID).Scan(
		&owner.protocol, &owner.targetHost, &owner.targetPort, &owner.identity)
	if errors.Is(err, sql.ErrNoRows) {
		return credentialOwner{}, false, nil
	}
	if err != nil {
		return credentialOwner{}, false, fmt.Errorf("load credential owner: %w", err)
	}
	return owner, true, nil
}

func credentialIDForOwnerTx(ctx context.Context, tx *sql.Tx, owner credentialOwner) (string, bool, error) {
	var credentialID string
	err := tx.QueryRowContext(ctx, `
		SELECT credential_id FROM credential_owners
		WHERE protocol = ? AND target_host = ? AND target_port = ? AND identity = ?`,
		owner.protocol, owner.targetHost, owner.targetPort, owner.identity).Scan(&credentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load owner credential: %w", err)
	}
	return credentialID, true, nil
}

func credentialRecordTx(ctx context.Context, tx *sql.Tx, credentialID string) (string, []byte, error) {
	var purpose string
	var ciphertext []byte
	err := tx.QueryRowContext(ctx, "SELECT purpose, ciphertext FROM credentials WHERE id = ?", credentialID).Scan(&purpose, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrCredentialNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("load credential record: %w", err)
	}
	return purpose, ciphertext, nil
}

func insertCredentialOwnerTx(ctx context.Context, tx *sql.Tx, credentialID string, owner credentialOwner) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO credential_owners (credential_id, protocol, target_host, target_port, identity)
		VALUES (?, ?, ?, ?, ?)`, credentialID, owner.protocol, owner.targetHost, owner.targetPort, owner.identity)
	if err != nil {
		return fmt.Errorf("save credential owner: %w", err)
	}
	return nil
}

func sshCredentialOwner(target SSHTarget) (credentialOwner, error) {
	host, err := canonicalIP(target.IP)
	if err != nil || target.Mode != SSHDirect || strings.TrimSpace(target.LoginUsername) == "" {
		return credentialOwner{}, ErrInvalidTarget
	}
	if _, err := normalizeSSHRemotePlatform(target.RemotePlatform); err != nil {
		return credentialOwner{}, err
	}
	port := target.SSHPort
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return credentialOwner{}, ErrInvalidTarget
	}
	return credentialOwner{
		protocol: credentialOwnerProtocolSSH, targetHost: host, targetPort: 0, identity: credentialIdentitySSH,
	}, nil
}

func databaseCredentialOwner(instance DatabaseInstance, identity string) (credentialOwner, error) {
	host, err := canonicalIP(instance.Host)
	if err != nil || instance.Port < 1 || instance.Port > 65535 {
		return credentialOwner{}, ErrInvalidTarget
	}
	switch identity {
	case credentialIdentityRead:
		if strings.TrimSpace(instance.ReadUsername) == "" {
			return credentialOwner{}, ErrInvalidTarget
		}
	case credentialIdentityWrite:
		if strings.TrimSpace(instance.WriteUsername) == "" {
			return credentialOwner{}, ErrInvalidTarget
		}
	default:
		return credentialOwner{}, ErrInvalidTarget
	}
	return credentialOwner{
		protocol: credentialOwnerProtocolDatabase, targetHost: host, targetPort: instance.Port, identity: identity,
	}, nil
}

func (owner credentialOwner) valid() bool {
	return owner.protocol != "" && owner.targetHost != "" && owner.identity != "" && owner.targetPort >= 0
}

func newCredentialID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "credential-" + hex.EncodeToString(bytes), nil
}

func expectCredential(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check credential update: %w", err)
	}
	if affected != 1 {
		return ErrCredentialNotFound
	}
	return nil
}
