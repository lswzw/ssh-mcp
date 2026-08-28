package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) SSHTarget(ctx context.Context, ip string) (SSHTarget, error) {
	canonical, err := canonicalIP(ip)
	if err != nil {
		return SSHTarget{}, ErrInvalidTarget
	}
	var target SSHTarget
	var enabled int
	var blacklistPatterns string
	var allowFileOperations int
	err = s.db.QueryRowContext(ctx, `
		SELECT ip, connection_mode, ssh_port, COALESCE(login_username, ''),
			COALESCE(credential_id, ''), command_blacklist_patterns, allow_file_operations,
			remote_platform, description, environment, enabled, identity_status, revision
		FROM ssh_targets WHERE ip = ? AND connection_mode = 'direct'`, canonical).Scan(
		&target.IP, &target.Mode, &target.SSHPort, &target.LoginUsername, &target.CredentialID,
		&blacklistPatterns, &allowFileOperations, &target.RemotePlatform, &target.Description, &target.Environment, &enabled, &target.IdentityStatus, &target.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return SSHTarget{}, ErrTargetNotFound
	}
	if err != nil {
		return SSHTarget{}, fmt.Errorf("load SSH target: %w", err)
	}
	if err := unmarshalCommandBlacklistPatterns(blacklistPatterns, &target.CommandBlacklistPatterns); err != nil {
		return SSHTarget{}, fmt.Errorf("decode SSH target command blacklist patterns: %w", err)
	}
	if err := validateStoredSSHRemotePlatform(target.RemotePlatform); err != nil {
		return SSHTarget{}, err
	}
	target.Enabled = enabled != 0
	target.AllowFileOperations = allowFileOperations != 0
	return target, nil
}

func (s *Store) DatabaseInstance(ctx context.Context, host string, port int) (DatabaseInstance, error) {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	var instance DatabaseInstance
	var enabled int
	err = s.db.QueryRowContext(ctx, `
		SELECT host, port, engine, default_database, read_username, write_username,
			COALESCE(read_credential_id, ''), COALESCE(write_credential_id, ''),
			description, environment, transport_security, transport_policy, tls_ca_path, enabled, database_major_version, version_status, revision
		FROM database_instances WHERE host = ? AND port = ?`, canonical, port).Scan(
		&instance.Host, &instance.Port, &instance.Engine, &instance.DefaultDatabase,
		&instance.ReadUsername, &instance.WriteUsername, &instance.ReadCredentialID,
		&instance.WriteCredentialID, &instance.Description, &instance.Environment,
		&instance.TransportSecurity, &instance.TransportPolicy, &instance.TLSCAPath, &enabled, &instance.MajorVersion, &instance.VersionStatus, &instance.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return DatabaseInstance{}, ErrTargetNotFound
	}
	if err != nil {
		return DatabaseInstance{}, fmt.Errorf("load database instance: %w", err)
	}
	instance.Enabled = enabled != 0
	return instance, nil
}
