package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ValidatedDatabaseInstanceConfiguration 表示已完成连通性校验、可原子落库的数据库配置变更。
type ValidatedDatabaseInstanceConfiguration struct {
	Instance      DatabaseInstance
	ReadPassword  []byte // 空值表示保留当前登记目标的只读专属凭据。
	WritePassword []byte // 空值表示保留当前可写凭据；同名读写账号则复用只读凭据。
}

// CommitValidatedDatabaseInstanceConfiguration 在一个本地事务中提交读写凭据和数据库登记目标。
func (v *Vault) CommitValidatedDatabaseInstanceConfiguration(ctx context.Context, configuration ValidatedDatabaseInstanceConfiguration) (DatabaseInstance, error) {
	instance, err := normalizeDatabaseInstanceConfiguration(configuration.Instance)
	if err != nil {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if strings.TrimSpace(instance.WriteUsername) == "" && len(configuration.WritePassword) > 0 {
		return DatabaseInstance{}, ErrInvalidCredential
	}
	readOwner, err := databaseCredentialOwner(instance, credentialIdentityRead)
	if err != nil {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	var writeOwner credentialOwner
	if instance.WriteUsername != "" {
		writeOwner, err = databaseCredentialOwner(instance, credentialIdentityWrite)
		if err != nil {
			return DatabaseInstance{}, ErrInvalidTarget
		}
	}

	var committed DatabaseInstance
	err = v.withDataKey(func(dataKey []byte) error {
		tx, err := v.store.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("开启数据库配置提交事务失败：%w", err)
		}
		defer func() { _ = tx.Rollback() }()

		current, exists, err := loadDatabaseInstanceTx(ctx, tx, instance.Host, instance.Port)
		if err != nil {
			return err
		}
		if len(configuration.ReadPassword) > 0 {
			if exists {
				if err := ensureCredentialOwnerTx(ctx, tx, current.ReadCredentialID, readOwner); err != nil {
					return err
				}
			}
			instance.ReadCredentialID, _, err = rotateOwnedCredentialTx(ctx, tx, dataKey, readOwner, "database-read-password", configuration.ReadPassword)
			if err != nil {
				return err
			}
		} else {
			if !exists {
				return ErrInvalidCredential
			}
			if err := ensureCredentialOwnerTx(ctx, tx, current.ReadCredentialID, readOwner); err != nil {
				return err
			}
			instance.ReadCredentialID = current.ReadCredentialID
		}

		if instance.WriteUsername != "" {
			reuseReadCredential := instance.WriteUsername == instance.ReadUsername && len(configuration.WritePassword) == 0 &&
				(!exists || current.WriteCredentialID == "")
			if reuseReadCredential {
				// A write account is explicitly configured, while its secret is
				// intentionally the same local credential as the read account.
				instance.WriteCredentialID = ""
			} else if len(configuration.WritePassword) > 0 {
				if exists {
					if err := ensureCredentialOwnerTx(ctx, tx, current.WriteCredentialID, writeOwner); err != nil {
						return err
					}
				}
				instance.WriteCredentialID, _, err = rotateOwnedCredentialTx(ctx, tx, dataKey, writeOwner, "database-write-password", configuration.WritePassword)
				if err != nil {
					return err
				}
			} else {
				if !exists || current.WriteCredentialID == "" {
					return ErrInvalidCredential
				}
				if err := ensureCredentialOwnerTx(ctx, tx, current.WriteCredentialID, writeOwner); err != nil {
					return err
				}
				instance.WriteCredentialID = current.WriteCredentialID
			}
		}

		if err := upsertDatabaseInstanceTx(ctx, tx, instance); err != nil {
			return err
		}
		if exists {
			if err := deleteUnreferencedCredentials(ctx, tx, current.ReadCredentialID, current.WriteCredentialID); err != nil {
				return err
			}
		}
		committed, exists, err = loadDatabaseInstanceTx(ctx, tx, instance.Host, instance.Port)
		if err != nil {
			return err
		}
		if !exists {
			return ErrTargetNotFound
		}
		if err := v.store.commitDatabaseInstanceConfiguration(tx); err != nil {
			return fmt.Errorf("提交数据库配置失败：%w", err)
		}
		return nil
	})
	if err != nil {
		return DatabaseInstance{}, err
	}
	return committed, nil
}

func (s *Store) commitDatabaseInstanceConfiguration(tx *sql.Tx) error {
	if s.databaseConfigurationCommit != nil {
		return s.databaseConfigurationCommit(tx)
	}
	return tx.Commit()
}

func loadDatabaseInstanceTx(ctx context.Context, tx *sql.Tx, host string, port int) (DatabaseInstance, bool, error) {
	var instance DatabaseInstance
	var enabled int
	err := tx.QueryRowContext(ctx, `
		SELECT host, port, engine, default_database, read_username, write_username,
			COALESCE(read_credential_id, ''), COALESCE(write_credential_id, ''),
			description, environment, transport_security, transport_policy, tls_ca_path, enabled, database_major_version, version_status, revision
		FROM database_instances WHERE host = ? AND port = ?`, host, port).Scan(
		&instance.Host, &instance.Port, &instance.Engine, &instance.DefaultDatabase,
		&instance.ReadUsername, &instance.WriteUsername, &instance.ReadCredentialID,
		&instance.WriteCredentialID, &instance.Description, &instance.Environment,
		&instance.TransportSecurity, &instance.TransportPolicy, &instance.TLSCAPath, &enabled, &instance.MajorVersion, &instance.VersionStatus, &instance.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return DatabaseInstance{}, false, nil
	}
	if err != nil {
		return DatabaseInstance{}, false, fmt.Errorf("读取数据库配置登记目标失败：%w", err)
	}
	instance.Enabled = enabled != 0
	return instance, true, nil
}
