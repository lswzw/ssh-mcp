package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

func (s *Store) UpsertSSHTarget(ctx context.Context, target SSHTarget) error {
	normalized, err := normalizeSSHTarget(target)
	if err != nil {
		return err
	}
	owner, err := sshCredentialOwner(normalized)
	if err != nil {
		return ErrInvalidTarget
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SSH target update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := ensureCredentialOwnerTx(ctx, tx, normalized.CredentialID, owner); err != nil {
		return err
	}
	if err := upsertSSHTargetTx(ctx, tx, normalized); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SSH target update: %w", err)
	}
	return nil
}

func upsertSSHTargetTx(ctx context.Context, tx *sql.Tx, target SSHTarget) error {
	enabled := boolToInt(target.Enabled)
	blacklistPatterns, err := marshalCommandBlacklistPatterns(target.CommandBlacklistPatterns)
	if err != nil {
		return fmt.Errorf("marshal SSH command blacklist patterns: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssh_targets (
			ip, connection_mode, ssh_port, login_username, credential_id,
			command_blacklist_patterns, allow_file_operations,
			remote_platform, description, environment, enabled, identity_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			connection_mode = excluded.connection_mode,
			ssh_port = excluded.ssh_port,
			login_username = excluded.login_username,
			credential_id = excluded.credential_id,
			command_blacklist_patterns = excluded.command_blacklist_patterns,
			allow_file_operations = excluded.allow_file_operations,
			remote_platform = excluded.remote_platform,
			description = excluded.description,
			environment = excluded.environment,
			enabled = excluded.enabled,
			identity_status = excluded.identity_status,
			revision = ssh_targets.revision + CASE WHEN
				ssh_targets.connection_mode IS NOT excluded.connection_mode OR
				ssh_targets.ssh_port IS NOT excluded.ssh_port OR
				ssh_targets.login_username IS NOT excluded.login_username OR
				ssh_targets.credential_id IS NOT excluded.credential_id OR
				ssh_targets.command_blacklist_patterns IS NOT excluded.command_blacklist_patterns OR
				ssh_targets.allow_file_operations IS NOT excluded.allow_file_operations OR
				ssh_targets.remote_platform IS NOT excluded.remote_platform OR
				ssh_targets.enabled IS NOT excluded.enabled OR
				ssh_targets.identity_status IS NOT excluded.identity_status
			THEN 1 ELSE 0 END,
			updated_at = excluded.updated_at`,
		target.IP, target.Mode, target.SSHPort, target.LoginUsername, target.CredentialID,
		blacklistPatterns, boolToInt(target.AllowFileOperations), target.RemotePlatform, target.Description, target.Environment, enabled, target.IdentityStatus, nowUnix(), nowUnix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

func (s *Store) ListSSHTargets(ctx context.Context) ([]SSHTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT ip, connection_mode, ssh_port, COALESCE(login_username, ''),
				COALESCE(credential_id, ''), command_blacklist_patterns, allow_file_operations,
				remote_platform, description, environment, enabled, identity_status, revision
		FROM ssh_targets WHERE connection_mode = 'direct' ORDER BY ip`)
	if err != nil {
		return nil, fmt.Errorf("list SSH targets: %w", err)
	}
	defer rows.Close()

	var targets []SSHTarget
	for rows.Next() {
		var target SSHTarget
		var enabled int
		var blacklistPatterns string
		var allowFileOperations int
		if err := rows.Scan(&target.IP, &target.Mode, &target.SSHPort, &target.LoginUsername,
			&target.CredentialID, &blacklistPatterns, &allowFileOperations, &target.RemotePlatform, &target.Description, &target.Environment, &enabled, &target.IdentityStatus, &target.Revision); err != nil {
			return nil, fmt.Errorf("scan SSH target: %w", err)
		}
		if err := unmarshalCommandBlacklistPatterns(blacklistPatterns, &target.CommandBlacklistPatterns); err != nil {
			return nil, fmt.Errorf("decode SSH target command blacklist patterns: %w", err)
		}
		if err := validateStoredSSHRemotePlatform(target.RemotePlatform); err != nil {
			return nil, err
		}
		target.Enabled = enabled != 0
		target.AllowFileOperations = allowFileOperations != 0
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate SSH targets: %w", err)
	}
	return targets, nil
}

func (s *Store) SetSSHTargetEnabled(ctx context.Context, ip string, enabled bool) error {
	canonical, err := canonicalIP(ip)
	if err != nil {
		return ErrInvalidTarget
	}
	if enabled {
		var current int
		err := s.db.QueryRowContext(ctx, "SELECT enabled FROM ssh_targets WHERE ip = ? AND connection_mode = 'direct'", canonical).Scan(&current)
		if err == sql.ErrNoRows {
			return ErrTargetNotFound
		}
		if err != nil {
			return fmt.Errorf("load SSH target state: %w", err)
		}
		if current == 0 {
			return ErrCandidateVerificationRequired
		}
	}
	result, err := s.db.ExecContext(ctx, "UPDATE ssh_targets SET enabled = ?, revision = revision + CASE WHEN enabled <> ? THEN 1 ELSE 0 END, updated_at = ? WHERE ip = ? AND connection_mode = 'direct'", boolToInt(enabled), boolToInt(enabled), nowUnix(), canonical)
	if err != nil {
		return fmt.Errorf("update SSH target state: %w", err)
	}
	return expectTarget(result)
}

// MarkSSHTargetIdentityUnconfirmed 持久隔离主机密钥异常的 SSH 目标。
// 后续重新启用必须经候选验证提交新的已确认主机身份。
func (s *Store) MarkSSHTargetIdentityUnconfirmed(ctx context.Context, ip string) error {
	canonical, err := canonicalIP(ip)
	if err != nil {
		return ErrInvalidTarget
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE ssh_targets
		SET enabled = 0,
			identity_status = ?,
			revision = revision + CASE WHEN enabled <> 0 OR identity_status <> ? THEN 1 ELSE 0 END,
			updated_at = ?
		WHERE ip = ? AND connection_mode = 'direct'`, SSHIdentityUnconfirmed, SSHIdentityUnconfirmed, nowUnix(), canonical)
	if err != nil {
		return fmt.Errorf("isolate SSH target identity: %w", err)
	}
	return expectTarget(result)
}

// DeleteSSHTarget removes an SSH target, its matching host key, and credentials
// that no remaining target references.
func (s *Store) DeleteSSHTarget(ctx context.Context, ip string) error {
	canonical, err := canonicalIP(ip)
	if err != nil {
		return ErrInvalidTarget
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SSH target deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var port int
	var credentialID string
	err = tx.QueryRowContext(ctx, `
		SELECT ssh_port, COALESCE(credential_id, '')
		FROM ssh_targets
		WHERE ip = ? AND connection_mode = 'direct'`, canonical).Scan(&port, &credentialID)
	if err == sql.ErrNoRows {
		return ErrTargetNotFound
	}
	if err != nil {
		return fmt.Errorf("load SSH target for deletion: %w", err)
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM ssh_targets WHERE ip = ? AND connection_mode = 'direct'", canonical)
	if err != nil {
		return fmt.Errorf("delete SSH target: %w", err)
	}
	if err := expectTarget(result); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM known_hosts WHERE host = ? AND port = ?", canonical, port); err != nil {
		return fmt.Errorf("delete SSH host key: %w", err)
	}
	if err := deleteUnreferencedCredentials(ctx, tx, credentialID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SSH target deletion: %w", err)
	}
	return nil
}

func (s *Store) UpsertDatabaseInstance(ctx context.Context, instance DatabaseInstance) error {
	normalized, err := normalizeDatabaseInstance(instance)
	if err != nil {
		return ErrInvalidTarget
	}
	readOwner, err := databaseCredentialOwner(normalized, credentialIdentityRead)
	if err != nil {
		return ErrInvalidTarget
	}
	var writeOwner credentialOwner
	if normalized.WriteCredentialID != "" {
		writeOwner, err = databaseCredentialOwner(normalized, credentialIdentityWrite)
		if err != nil {
			return ErrInvalidTarget
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database target update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := ensureCredentialOwnerTx(ctx, tx, normalized.ReadCredentialID, readOwner); err != nil {
		return err
	}
	if normalized.WriteCredentialID != "" {
		if err := ensureCredentialOwnerTx(ctx, tx, normalized.WriteCredentialID, writeOwner); err != nil {
			return err
		}
	}
	if err := upsertDatabaseInstanceTx(ctx, tx, normalized); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database target update: %w", err)
	}
	return nil
}

func upsertDatabaseInstanceTx(ctx context.Context, tx *sql.Tx, instance DatabaseInstance) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO database_instances (
			host, port, engine, default_database, read_username, write_username,
			read_credential_id, write_credential_id, description, environment,
			transport_security, transport_policy, tls_ca_path, enabled, database_major_version, version_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, port) DO UPDATE SET
			engine = excluded.engine,
			default_database = excluded.default_database,
			read_username = excluded.read_username,
			write_username = excluded.write_username,
			read_credential_id = excluded.read_credential_id,
			write_credential_id = excluded.write_credential_id,
			description = excluded.description,
			environment = excluded.environment,
			transport_security = excluded.transport_security,
			transport_policy = excluded.transport_policy,
			tls_ca_path = excluded.tls_ca_path,
			enabled = excluded.enabled,
			database_major_version = excluded.database_major_version,
			version_status = excluded.version_status,
			revision = database_instances.revision + CASE WHEN
				database_instances.engine IS NOT excluded.engine OR
				database_instances.default_database IS NOT excluded.default_database OR
				database_instances.read_username IS NOT excluded.read_username OR
				database_instances.write_username IS NOT excluded.write_username OR
				database_instances.read_credential_id IS NOT excluded.read_credential_id OR
				database_instances.write_credential_id IS NOT excluded.write_credential_id OR
				database_instances.transport_policy IS NOT excluded.transport_policy OR
				database_instances.tls_ca_path IS NOT excluded.tls_ca_path OR
				database_instances.enabled IS NOT excluded.enabled
			THEN 1 ELSE 0 END,
			updated_at = excluded.updated_at`,
		instance.Host, instance.Port, instance.Engine, instance.DefaultDatabase,
		instance.ReadUsername, instance.WriteUsername, instance.ReadCredentialID,
		instance.WriteCredentialID, instance.Description, instance.Environment,
		instance.TransportSecurity, instance.TransportPolicy, instance.TLSCAPath,
		boolToInt(instance.Enabled), instance.MajorVersion, instance.VersionStatus, nowUnix(), nowUnix())
	if err != nil {
		return mapConstraintError(err)
	}
	return nil
}

func (s *Store) ListDatabaseInstances(ctx context.Context) ([]DatabaseInstance, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT host, port, engine, default_database, read_username, write_username,
			COALESCE(read_credential_id, ''), COALESCE(write_credential_id, ''),
			description, environment, transport_security, transport_policy, tls_ca_path, enabled, database_major_version, version_status, revision
		FROM database_instances ORDER BY host, port`)
	if err != nil {
		return nil, fmt.Errorf("list database instances: %w", err)
	}
	defer rows.Close()

	var instances []DatabaseInstance
	for rows.Next() {
		var instance DatabaseInstance
		var enabled int
		if err := rows.Scan(&instance.Host, &instance.Port, &instance.Engine, &instance.DefaultDatabase,
			&instance.ReadUsername, &instance.WriteUsername, &instance.ReadCredentialID,
			&instance.WriteCredentialID, &instance.Description, &instance.Environment,
			&instance.TransportSecurity, &instance.TransportPolicy, &instance.TLSCAPath, &enabled, &instance.MajorVersion, &instance.VersionStatus, &instance.Revision); err != nil {
			return nil, fmt.Errorf("scan database instance: %w", err)
		}
		instance.Enabled = enabled != 0
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate database instances: %w", err)
	}
	return instances, nil
}

func (s *Store) SetDatabaseInstanceEnabled(ctx context.Context, host string, port int, enabled bool) error {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 {
		return ErrInvalidTarget
	}
	if enabled {
		var current int
		err := s.db.QueryRowContext(ctx, "SELECT enabled FROM database_instances WHERE host = ? AND port = ?", canonical, port).Scan(&current)
		if err == sql.ErrNoRows {
			return ErrTargetNotFound
		}
		if err != nil {
			return fmt.Errorf("load database target state: %w", err)
		}
		if current == 0 {
			return ErrCandidateVerificationRequired
		}
	}
	result, err := s.db.ExecContext(ctx, "UPDATE database_instances SET enabled = ?, revision = revision + CASE WHEN enabled <> ? THEN 1 ELSE 0 END, updated_at = ? WHERE host = ? AND port = ?", boolToInt(enabled), boolToInt(enabled), nowUnix(), canonical, port)
	if err != nil {
		return fmt.Errorf("update database instance state: %w", err)
	}
	return expectTarget(result)
}

// DeleteDatabaseInstance removes a database target and credentials that no
// remaining target references.
func (s *Store) DeleteDatabaseInstance(ctx context.Context, host string, port int) error {
	canonical, err := canonicalIP(host)
	if err != nil || port < 1 || port > 65535 {
		return ErrInvalidTarget
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database target deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var readCredentialID, writeCredentialID string
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(read_credential_id, ''), COALESCE(write_credential_id, '')
		FROM database_instances
		WHERE host = ? AND port = ?`, canonical, port).Scan(&readCredentialID, &writeCredentialID)
	if err == sql.ErrNoRows {
		return ErrTargetNotFound
	}
	if err != nil {
		return fmt.Errorf("load database target for deletion: %w", err)
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM database_instances WHERE host = ? AND port = ?", canonical, port)
	if err != nil {
		return fmt.Errorf("delete database target: %w", err)
	}
	if err := expectTarget(result); err != nil {
		return err
	}
	if err := deleteUnreferencedCredentials(ctx, tx, readCredentialID, writeCredentialID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database target deletion: %w", err)
	}
	return nil
}

func deleteUnreferencedCredentials(ctx context.Context, tx *sql.Tx, ids ...string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result, err := tx.ExecContext(ctx, `
			DELETE FROM credentials
			WHERE id = ?
				AND NOT EXISTS (SELECT 1 FROM ssh_targets WHERE credential_id = ?)
				AND NOT EXISTS (
					SELECT 1 FROM database_instances
					WHERE read_credential_id = ? OR write_credential_id = ?
				)`, id, id, id, id)
		if err != nil {
			return fmt.Errorf("delete unreferenced credential: %w", err)
		}
		if _, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("check unreferenced credential deletion: %w", err)
		}
	}
	return nil
}

func normalizeSSHTarget(target SSHTarget) (SSHTarget, error) {
	return normalizeSSHTargetFields(target, true)
}

func normalizeSSHTargetConfiguration(target SSHTarget) (SSHTarget, error) {
	target.CredentialID = ""
	return normalizeSSHTargetFields(target, false)
}

// ValidateSSHTargetConfiguration checks all non-secret SSH target settings
// before a candidate connection is attempted.
func ValidateSSHTargetConfiguration(target SSHTarget) error {
	_, err := normalizeSSHTargetConfiguration(target)
	return err
}

func normalizeSSHTargetFields(target SSHTarget, requireCredential bool) (SSHTarget, error) {
	ip, err := canonicalIP(target.IP)
	if target.IdentityStatus == "" {
		target.IdentityStatus = SSHIdentityUnconfirmed
	}
	if err != nil || target.Mode != SSHDirect || target.LoginUsername == "" || (requireCredential && target.CredentialID == "") {
		return SSHTarget{}, ErrInvalidTarget
	}
	if !validSSHIdentityStatus(target.IdentityStatus) {
		return SSHTarget{}, ErrInvalidTarget
	}
	if target.SSHPort == 0 {
		target.SSHPort = 22
	}
	if target.SSHPort < 1 || target.SSHPort > 65535 {
		return SSHTarget{}, ErrInvalidTarget
	}
	platform, err := normalizeSSHRemotePlatform(target.RemotePlatform)
	if err != nil {
		return SSHTarget{}, err
	}
	blacklistPatterns, err := normalizeCommandBlacklistPatterns(target.CommandBlacklistPatterns)
	if err != nil {
		return SSHTarget{}, ErrInvalidTarget
	}
	target.IP = ip
	target.RemotePlatform = platform
	target.CommandBlacklistPatterns = blacklistPatterns
	return target, nil
}

func normalizeSSHRemotePlatform(value SSHRemotePlatform) (SSHRemotePlatform, error) {
	value = SSHRemotePlatform(strings.ToLower(strings.TrimSpace(string(value))))
	if value == "" {
		return SSHRemotePlatformLinux, nil
	}
	if value != SSHRemotePlatformLinux {
		return "", ErrUnsupportedRemotePlatform
	}
	return value, nil
}

func validateStoredSSHRemotePlatform(value SSHRemotePlatform) error {
	if value != SSHRemotePlatformLinux {
		return ErrUnsupportedRemotePlatform
	}
	return nil
}

func normalizeCommandBlacklistPatterns(values []string) ([]string, error) {
	if len(values) > 128 {
		return nil, ErrInvalidTarget
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
			return nil, ErrInvalidTarget
		}
		if _, err := regexp.Compile(value); err != nil {
			return nil, ErrInvalidTarget
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func marshalCommandBlacklistPatterns(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func unmarshalCommandBlacklistPatterns(encoded string, destination *[]string) error {
	if strings.TrimSpace(encoded) == "" {
		encoded = "[]"
	}
	if err := json.Unmarshal([]byte(encoded), destination); err != nil {
		return err
	}
	normalized, err := normalizeCommandBlacklistPatterns(*destination)
	if err != nil {
		return err
	}
	*destination = normalized
	return nil
}

func normalizeDatabaseInstance(instance DatabaseInstance) (DatabaseInstance, error) {
	return normalizeDatabaseInstanceFields(instance, true)
}

func normalizeDatabaseInstanceConfiguration(instance DatabaseInstance) (DatabaseInstance, error) {
	instance.ReadCredentialID = ""
	instance.WriteCredentialID = ""
	return normalizeDatabaseInstanceFields(instance, false)
}

func normalizeDatabaseInstanceFields(instance DatabaseInstance, requireCredentials bool) (DatabaseInstance, error) {
	host, err := canonicalIP(instance.Host)
	instance.ReadUsername = strings.TrimSpace(instance.ReadUsername)
	instance.WriteUsername = strings.TrimSpace(instance.WriteUsername)
	instance.ReadCredentialID = strings.TrimSpace(instance.ReadCredentialID)
	instance.WriteCredentialID = strings.TrimSpace(instance.WriteCredentialID)
	instance.TLSCAPath = strings.TrimSpace(instance.TLSCAPath)
	if instance.TransportPolicy == "" {
		// Pre-policy callers and migrated targets retain the intentionally
		// supported legacy behavior until an operator selects verified TLS.
		instance.TransportPolicy = DatabaseLegacyPlaintext
	}
	if instance.VersionStatus == "" {
		instance.VersionStatus = DatabaseVersionUnverified
		instance.MajorVersion = 0
	}
	writeUsesReadCredential := instance.WriteUsername != "" &&
		instance.WriteUsername == instance.ReadUsername && instance.WriteCredentialID == ""
	if err != nil || instance.Port < 1 || instance.Port > 65535 || !validEngine(instance.Engine) ||
		instance.ReadUsername == "" || (requireCredentials && instance.ReadCredentialID == "") ||
		!validTransportSecurity(instance.TransportSecurity) || !validDatabaseTransportPolicy(instance.TransportPolicy) ||
		!validDatabaseVersionStatus(instance.VersionStatus) ||
		(requireCredentials && instance.WriteUsername != "" && instance.WriteCredentialID == "" && !writeUsesReadCredential) ||
		(instance.WriteUsername == "" && instance.WriteCredentialID != "") {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if (instance.VersionStatus == DatabaseVersionVerified && instance.MajorVersion < 1) ||
		(instance.VersionStatus == DatabaseVersionUnverified && instance.MajorVersion != 0) {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if instance.WriteCredentialID != "" && instance.ReadCredentialID == instance.WriteCredentialID {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if instance.TransportPolicy == DatabaseTLSVerified && (instance.TLSCAPath == "" || !filepath.IsAbs(instance.TLSCAPath) || strings.ContainsRune(instance.TLSCAPath, '\x00')) {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if instance.TransportPolicy == DatabaseLegacyPlaintext && instance.TLSCAPath != "" {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	if instance.Engine == EnginePostgreSQL && strings.TrimSpace(instance.DefaultDatabase) == "" {
		return DatabaseInstance{}, ErrInvalidTarget
	}
	instance.Host = host
	return instance, nil
}

func expectTarget(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check target update: %w", err)
	}
	if affected != 1 {
		return ErrTargetNotFound
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
