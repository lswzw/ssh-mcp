package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ValidatedSSHTargetConfiguration 表示已完成主机身份确认和连通性校验、可原子落库的 SSH 配置变更。
type ValidatedSSHTargetConfiguration struct {
	Target               SSHTarget
	Password             []byte // 空值表示保留当前登记目标的专属凭据。
	ConfirmedFingerprint string
}

// CommitValidatedSSHTargetConfiguration 在一个本地事务中提交凭据、登记目标和已验证的主机身份。
func (v *Vault) CommitValidatedSSHTargetConfiguration(ctx context.Context, configuration ValidatedSSHTargetConfiguration) (SSHTarget, error) {
	configuration.Target.IdentityStatus = SSHIdentityVerified
	target, err := normalizeSSHTargetConfiguration(configuration.Target)
	if err != nil {
		return SSHTarget{}, err
	}
	fingerprint := strings.TrimSpace(configuration.ConfirmedFingerprint)
	if fingerprint == "" {
		return SSHTarget{}, ErrInvalidTarget
	}
	owner, err := sshCredentialOwner(target)
	if err != nil {
		return SSHTarget{}, ErrInvalidTarget
	}

	var committed SSHTarget
	err = v.withDataKey(func(dataKey []byte) error {
		tx, err := v.store.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("开启 SSH 配置提交事务失败：%w", err)
		}
		defer func() { _ = tx.Rollback() }()

		current, exists, err := loadSSHTargetTx(ctx, tx, target.IP)
		if err != nil {
			return err
		}
		if len(configuration.Password) > 0 {
			if exists {
				if err := ensureCredentialOwnerTx(ctx, tx, current.CredentialID, owner); err != nil {
					return err
				}
			}
			target.CredentialID, _, err = rotateOwnedCredentialTx(ctx, tx, dataKey, owner, "ssh-password", configuration.Password)
			if err != nil {
				return err
			}
		} else {
			if !exists {
				return ErrInvalidCredential
			}
			if err := ensureCredentialOwnerTx(ctx, tx, current.CredentialID, owner); err != nil {
				return err
			}
			target.CredentialID = current.CredentialID
		}

		if err := upsertSSHTargetTx(ctx, tx, target); err != nil {
			return err
		}
		if exists && current.SSHPort != target.SSHPort {
			if _, err := tx.ExecContext(ctx, "DELETE FROM known_hosts WHERE host = ? AND port = ?", current.IP, current.SSHPort); err != nil {
				return fmt.Errorf("删除旧 SSH 主机身份失败：%w", err)
			}
		}
		hostIdentityChanged, err := upsertValidatedHostKeyTx(ctx, tx, target.IP, target.SSHPort, fingerprint)
		if err != nil {
			return err
		}
		if exists && current.SSHPort == target.SSHPort && hostIdentityChanged {
			if _, err := tx.ExecContext(ctx, `
				UPDATE ssh_targets
				SET revision = revision + 1, updated_at = ?
				WHERE ip = ? AND connection_mode = 'direct'`, nowUnix(), target.IP); err != nil {
				return fmt.Errorf("推进 SSH 主机身份执行版本失败：%w", err)
			}
		}
		if exists {
			if err := deleteUnreferencedCredentials(ctx, tx, current.CredentialID); err != nil {
				return err
			}
		}
		committed, exists, err = loadSSHTargetTx(ctx, tx, target.IP)
		if err != nil {
			return err
		}
		if !exists {
			return ErrTargetNotFound
		}
		if err := v.store.commitSSHTargetConfiguration(tx); err != nil {
			return fmt.Errorf("提交 SSH 配置失败：%w", err)
		}
		return nil
	})
	if err != nil {
		return SSHTarget{}, err
	}
	return committed, nil
}

func (s *Store) commitSSHTargetConfiguration(tx *sql.Tx) error {
	if s.sshConfigurationCommit != nil {
		return s.sshConfigurationCommit(tx)
	}
	return tx.Commit()
}

func loadSSHTargetTx(ctx context.Context, tx *sql.Tx, ip string) (SSHTarget, bool, error) {
	var target SSHTarget
	var enabled int
	var blacklistPatterns string
	var allowFileOperations int
	err := tx.QueryRowContext(ctx, `
		SELECT ip, connection_mode, ssh_port, COALESCE(login_username, ''),
			COALESCE(credential_id, ''), command_blacklist_patterns, allow_file_operations,
			remote_platform, description, environment, enabled, identity_status, revision
		FROM ssh_targets WHERE ip = ? AND connection_mode = 'direct'`, ip).Scan(
		&target.IP, &target.Mode, &target.SSHPort, &target.LoginUsername, &target.CredentialID,
		&blacklistPatterns, &allowFileOperations, &target.RemotePlatform, &target.Description, &target.Environment, &enabled, &target.IdentityStatus, &target.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return SSHTarget{}, false, nil
	}
	if err != nil {
		return SSHTarget{}, false, fmt.Errorf("读取 SSH 配置登记目标失败：%w", err)
	}
	if err := unmarshalCommandBlacklistPatterns(blacklistPatterns, &target.CommandBlacklistPatterns); err != nil {
		return SSHTarget{}, false, fmt.Errorf("解码 SSH 配置命令黑名单失败：%w", err)
	}
	if err := validateStoredSSHRemotePlatform(target.RemotePlatform); err != nil {
		return SSHTarget{}, false, err
	}
	target.Enabled = enabled != 0
	target.AllowFileOperations = allowFileOperations != 0
	return target, true, nil
}
