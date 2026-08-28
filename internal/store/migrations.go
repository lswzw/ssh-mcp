package store

import (
	"context"
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	sql     string
	apply   func(context.Context, *sql.Tx) error
}

var migrations = []migration{
	{
		version: 1,
		sql: `
			CREATE TABLE metadata (
				key TEXT PRIMARY KEY,
				value BLOB NOT NULL
			);

			CREATE TABLE key_envelopes (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				version INTEGER NOT NULL,
				salt BLOB NOT NULL,
				nonce BLOB NOT NULL,
				ciphertext BLOB NOT NULL,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			);

			CREATE TABLE credentials (
				id TEXT PRIMARY KEY,
				purpose TEXT NOT NULL,
				ciphertext BLOB NOT NULL,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			);

			CREATE TABLE ssh_targets (
				ip TEXT PRIMARY KEY,
				connection_mode TEXT NOT NULL CHECK (connection_mode = 'direct'),
				ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
				login_username TEXT,
				credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
				description TEXT NOT NULL DEFAULT '',
				environment TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			);

			CREATE TABLE database_instances (
				host TEXT NOT NULL,
				port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
				engine TEXT NOT NULL CHECK (engine IN ('mysql', 'postgresql')),
				default_database TEXT NOT NULL DEFAULT '',
				read_credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
				write_credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
				description TEXT NOT NULL DEFAULT '',
				environment TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				UNIQUE (host, port)
			);

			CREATE TABLE known_hosts (
				host TEXT PRIMARY KEY,
				port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
				fingerprint TEXT NOT NULL,
				confirmed_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			);

			CREATE TABLE sessions (
				id TEXT PRIMARY KEY,
				state TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				last_activity_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			);
		`,
	},
	{
		version: 2,
		sql: `
			CREATE TABLE known_hosts_next (
				host TEXT NOT NULL,
				port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
				fingerprint TEXT NOT NULL,
				confirmed_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				PRIMARY KEY (host, port)
			);

			INSERT INTO known_hosts_next (host, port, fingerprint, confirmed_at, updated_at)
			SELECT host, port, fingerprint, confirmed_at, updated_at FROM known_hosts;

			DROP TABLE known_hosts;
			ALTER TABLE known_hosts_next RENAME TO known_hosts;
		`,
	},
	{
		version: 3,
		sql: `
			ALTER TABLE database_instances ADD COLUMN read_username TEXT NOT NULL DEFAULT '';
			ALTER TABLE database_instances ADD COLUMN write_username TEXT NOT NULL DEFAULT '';
			ALTER TABLE database_instances ADD COLUMN transport_security TEXT NOT NULL DEFAULT '';
		`,
	},
	{
		version: 4,
		apply:   repairDatabaseInstanceAccountColumns,
	},
	{
		version: 6,
		apply:   removePersistedQueryRules,
	},
	{
		version: 7,
		sql: `
			DROP TABLE IF EXISTS audit_entries;
		`,
	},
	{
		version: 8,
		apply:   addTransportPolicyAndTargetRevisions,
	},
	{
		version: 9,
		sql: `
			CREATE TABLE credential_owners (
				credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
				protocol TEXT NOT NULL,
				target_host TEXT NOT NULL,
				target_port INTEGER NOT NULL,
				identity TEXT NOT NULL,
				UNIQUE (protocol, target_host, target_port, identity)
			);
		`,
	},
	{
		version: 10,
		apply:   addTargetVerificationState,
	},
	{
		version: 11,
		apply:   addDatabaseResourceBoundaries,
	},
	{
		version: 12,
		apply:   replaceDatabaseResourceBoundariesWithCommandBlacklist,
	},
	{
		version: 13,
		apply:   addSSHFileReadRoots,
	},
	{
		version: 14,
		apply:   addSSHDeploymentProfiles,
	},
	{
		version: 15,
		apply:   addSSHRemotePlatform,
	},
	{
		version: 16,
		apply:   addSSHFileOperationsCapability,
	},
	{
		version: 17,
		apply:   removeLegacySSHFileConfiguration,
	},
}

func addSSHFileReadRoots(ctx context.Context, tx *sql.Tx) error {
	return addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "file_read_roots", definition: "TEXT NOT NULL DEFAULT '[]'"},
	})
}

func addSSHDeploymentProfiles(ctx context.Context, tx *sql.Tx) error {
	return addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "deployment_profiles", definition: "TEXT NOT NULL DEFAULT '[]'"},
	})
}

func addSSHRemotePlatform(ctx context.Context, tx *sql.Tx) error {
	return addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "remote_platform", definition: "TEXT NOT NULL DEFAULT 'linux'"},
	})
}

// addSSHFileOperationsCapability replaces the former per-root/profile file
// configuration with one explicit target capability. Existing targets retain
// the permissive default so upgrading does not unexpectedly disable access.
func addSSHFileOperationsCapability(ctx context.Context, tx *sql.Tx) error {
	return addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "allow_file_operations", definition: "INTEGER NOT NULL DEFAULT 1 CHECK (allow_file_operations IN (0, 1))"},
	})
}

// removeLegacySSHFileConfiguration removes the former per-root and deployment
// profile columns after their migration versions have been applied. Keeping
// v13/v14 in the migration history lets old databases upgrade in order, while
// the rebuilt table ensures new and upgraded databases expose only the current
// target configuration.
func removeLegacySSHFileConfiguration(ctx context.Context, tx *sql.Tx) error {
	exists, err := tableExistsTx(ctx, tx, "ssh_targets")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(ssh_targets)")
	if err != nil {
		return fmt.Errorf("inspect SSH target columns for legacy file configuration cleanup: %w", err)
	}
	defer rows.Close()
	legacy := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan SSH target columns for legacy file configuration cleanup: %w", err)
		}
		if name == "file_read_roots" || name == "deployment_profiles" {
			legacy = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate SSH target columns for legacy file configuration cleanup: %w", err)
	}
	if !legacy {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
		CREATE TABLE ssh_targets_next (
			ip TEXT PRIMARY KEY,
			connection_mode TEXT NOT NULL CHECK (connection_mode = 'direct'),
			ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
			login_username TEXT,
			credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
			command_blacklist_patterns TEXT NOT NULL DEFAULT '[]',
			allow_file_operations INTEGER NOT NULL DEFAULT 1 CHECK (allow_file_operations IN (0, 1)),
			remote_platform TEXT NOT NULL DEFAULT 'linux',
			description TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			identity_status TEXT NOT NULL DEFAULT 'identity_unconfirmed',
			revision INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);

		INSERT INTO ssh_targets_next (
			ip, connection_mode, ssh_port, login_username, credential_id,
			command_blacklist_patterns, allow_file_operations, remote_platform,
			description, environment, enabled, identity_status, revision,
			created_at, updated_at
		)
		SELECT
			ip, connection_mode, ssh_port, login_username, credential_id,
			command_blacklist_patterns, allow_file_operations, remote_platform,
			description, environment, enabled, identity_status, revision,
			created_at, updated_at
		FROM ssh_targets;

		DROP TABLE ssh_targets;
		ALTER TABLE ssh_targets_next RENAME TO ssh_targets;
	`)
	if err != nil {
		return fmt.Errorf("remove legacy SSH file configuration columns: %w", err)
	}
	return nil
}

func addDatabaseResourceBoundaries(ctx context.Context, tx *sql.Tx) error {
	return addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "database_containers", definition: "TEXT NOT NULL DEFAULT '[]'"},
		{name: "database_volumes", definition: "TEXT NOT NULL DEFAULT '[]'"},
		{name: "database_data_paths", definition: "TEXT NOT NULL DEFAULT '[]'"},
	})
}

// replaceDatabaseResourceBoundariesWithCommandBlacklist deliberately drops
// registrations that cannot be translated safely into command regexes.
func replaceDatabaseResourceBoundariesWithCommandBlacklist(ctx context.Context, tx *sql.Tx) error {
	exists, err := tableExistsTx(ctx, tx, "ssh_targets")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
		CREATE TABLE ssh_targets_next (
			ip TEXT PRIMARY KEY,
			connection_mode TEXT NOT NULL CHECK (connection_mode = 'direct'),
			ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
			login_username TEXT,
			credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
			command_blacklist_patterns TEXT NOT NULL DEFAULT '[]',
			description TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			identity_status TEXT NOT NULL DEFAULT 'identity_unconfirmed',
			revision INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);

		INSERT INTO ssh_targets_next (
			ip, connection_mode, ssh_port, login_username, credential_id,
			command_blacklist_patterns, description, environment, enabled,
			identity_status, revision, created_at, updated_at
		)
		SELECT
			ip, connection_mode, ssh_port, login_username, credential_id,
			'[]', description, environment, enabled,
			identity_status, revision, created_at, updated_at
		FROM ssh_targets;

		DROP TABLE ssh_targets;
		ALTER TABLE ssh_targets_next RENAME TO ssh_targets;
	`)
	if err != nil {
		return fmt.Errorf("replace SSH database resource boundaries with command blacklist: %w", err)
	}
	return nil
}

func addTargetVerificationState(ctx context.Context, tx *sql.Tx) error {
	if err := addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "identity_status", definition: "TEXT NOT NULL DEFAULT 'identity_unconfirmed'"},
	}); err != nil {
		return err
	}
	if err := addColumnsIfTableExists(ctx, tx, "database_instances", []struct {
		name       string
		definition string
	}{
		{name: "database_major_version", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "version_status", definition: "TEXT NOT NULL DEFAULT 'version_unverified'"},
	}); err != nil {
		return err
	}

	sshTargetsExist, err := tableExistsTx(ctx, tx, "ssh_targets")
	if err != nil {
		return err
	}
	if !sshTargetsExist {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE ssh_targets
		SET identity_status = 'identity_verified'
		WHERE EXISTS (
			SELECT 1 FROM known_hosts
			WHERE known_hosts.host = ssh_targets.ip
				AND known_hosts.port = ssh_targets.ssh_port
		)`)
	if err != nil {
		return fmt.Errorf("mark previously pinned SSH identities: %w", err)
	}
	return nil
}

func addTransportPolicyAndTargetRevisions(ctx context.Context, tx *sql.Tx) error {
	if err := addColumnsIfTableExists(ctx, tx, "ssh_targets", []struct {
		name       string
		definition string
	}{
		{name: "revision", definition: "INTEGER NOT NULL DEFAULT 1"},
	}); err != nil {
		return err
	}
	return addColumnsIfTableExists(ctx, tx, "database_instances", []struct {
		name       string
		definition string
	}{
		{name: "transport_policy", definition: "TEXT NOT NULL DEFAULT 'legacy_plaintext'"},
		{name: "tls_ca_path", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "revision", definition: "INTEGER NOT NULL DEFAULT 1"},
	})
}

func addColumnsIfTableExists(ctx context.Context, tx *sql.Tx, table string, columns []struct {
	name       string
	definition string
}) error {
	exists, err := tableExistsTx(ctx, tx, table)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	existing := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan %s column: %w", table, err)
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s columns: %w", table, err)
	}
	for _, column := range columns {
		if existing[column.name] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column.name+" "+column.definition); err != nil {
			return fmt.Errorf("add %s column %s: %w", table, column.name, err)
		}
	}
	return nil
}

func tableExistsTx(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)", table).Scan(&exists); err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return exists, nil
}

func removePersistedQueryRules(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS ssh_query_rules"); err != nil {
		return fmt.Errorf("remove obsolete SSH query rules: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS approval_requests"); err != nil {
		return fmt.Errorf("remove obsolete approval requests: %w", err)
	}
	return nil
}

// repairDatabaseInstanceAccountColumns makes an earlier partial v3 migration
// recoverable. Some existing state files recorded v3 without all three columns.
func repairDatabaseInstanceAccountColumns(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(database_instances)")
	if err != nil {
		return fmt.Errorf("inspect database instance columns: %w", err)
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan database instance column: %w", err)
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database instance columns: %w", err)
	}

	columns := []struct {
		name       string
		definition string
	}{
		{name: "read_username", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "write_username", definition: "TEXT NOT NULL DEFAULT ''"},
		{name: "transport_security", definition: "TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range columns {
		if existing[column.name] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE database_instances ADD COLUMN "+column.name+" "+column.definition); err != nil {
			return fmt.Errorf("add database instance column %s: %w", column.name, err)
		}
	}
	return nil
}
