package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestOpenAddsFileOperationsCapabilityMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
		INSERT INTO schema_migrations (version, applied_at) VALUES
			(1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0),
			(7, 0), (8, 0), (9, 0), (10, 0), (11, 0), (12, 0),
			(13, 0), (14, 0), (15, 0);
		CREATE TABLE credentials (id TEXT PRIMARY KEY);
		CREATE TABLE ssh_targets (
			ip TEXT PRIMARY KEY,
			connection_mode TEXT NOT NULL CHECK (connection_mode = 'direct'),
			ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
			login_username TEXT,
			credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
			command_blacklist_patterns TEXT NOT NULL DEFAULT '[]',
			file_read_roots TEXT NOT NULL DEFAULT '[]',
			deployment_profiles TEXT NOT NULL DEFAULT '[]',
			remote_platform TEXT NOT NULL DEFAULT 'linux',
			description TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			identity_status TEXT NOT NULL DEFAULT 'identity_unconfirmed',
			revision INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		INSERT INTO ssh_targets (
			ip, connection_mode, ssh_port, login_username, command_blacklist_patterns,
			file_read_roots, deployment_profiles, remote_platform, description,
			environment, enabled, identity_status, revision, created_at, updated_at
		) VALUES ('192.0.2.200', 'direct', 22, 'ops', '[]', '[]', '[]', 'linux',
			'legacy', 'test', 1, 'identity_verified', 9, 1, 1);`)
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create v15 database: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var hasColumn bool
	var notNull int
	var defaultValue any
	rows, err := store.db.Query("PRAGMA table_info(ssh_targets)")
	if err != nil {
		t.Fatalf("inspect SSH target columns: %v", err)
	}
	for rows.Next() {
		var cid, primaryKey int
		var name, columnType string
		var value any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &value, &primaryKey); err != nil {
			_ = rows.Close()
			t.Fatalf("scan SSH target column: %v", err)
		}
		if name == "allow_file_operations" {
			hasColumn = true
			defaultValue = value
		}
		if name == "file_read_roots" || name == "deployment_profiles" {
			t.Fatalf("obsolete SSH target column %q remains after cleanup migration", name)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatalf("iterate SSH target columns: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close SSH target columns: %v", err)
	}
	if !hasColumn {
		t.Fatal("ssh_targets is missing allow_file_operations")
	}
	if got := fmt.Sprint(defaultValue); got != "1" && got != "'1'" {
		t.Fatalf("allow_file_operations default = %v, want 1", defaultValue)
	}

	target, err := store.SSHTarget(context.Background(), "192.0.2.200")
	if err != nil {
		t.Fatalf("load migrated target: %v", err)
	}
	if !target.AllowFileOperations {
		t.Fatal("migrated target has file operations disabled; want permissive default")
	}
	var migrated bool
	if err := store.db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 17)").Scan(&migrated); err != nil {
		t.Fatalf("check file operations cleanup migration: %v", err)
	}
	if !migrated {
		t.Fatal("file operations cleanup migration was not recorded")
	}
}

func TestOpenFreshSchemaOmitsLegacySSHFileConfiguration(t *testing.T) {
	store := openTargetTestStore(t)
	rows, err := store.db.Query("PRAGMA table_info(ssh_targets)")
	if err != nil {
		t.Fatalf("inspect fresh SSH target columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan fresh SSH target column: %v", err)
		}
		if name == "file_read_roots" || name == "deployment_profiles" {
			t.Fatalf("fresh schema retains obsolete SSH target column %q", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fresh SSH target columns: %v", err)
	}
}

func TestAddSSHTargetDefaultsFileOperationsToEnabled(t *testing.T) {
	store := openTargetTestStore(t)
	if err := store.AddSSHTarget(context.Background(), SSHTarget{
		IP:   "192.0.2.201",
		Mode: SSHDirect,
	}); err != nil {
		t.Fatalf("AddSSHTarget() error = %v", err)
	}
	target, err := store.SSHTarget(context.Background(), "192.0.2.201")
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if !target.AllowFileOperations {
		t.Fatal("new SSH target has file operations disabled; want true by default")
	}
}

func TestSSHTargetPersistsFileOperationsCapability(t *testing.T) {
	store := openTargetTestStore(t)
	seedTargetCredential(t, store, "ssh-file-operations")
	target := SSHTarget{
		IP:                  "192.0.2.202",
		Mode:                SSHDirect,
		LoginUsername:       "ops",
		CredentialID:        "ssh-file-operations",
		Enabled:             true,
		AllowFileOperations: false,
	}
	if err := store.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	saved, err := store.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if saved.AllowFileOperations {
		t.Fatal("explicitly disabled file operations were persisted as enabled")
	}
	initialRevision := saved.Revision

	saved.AllowFileOperations = true
	if err := store.UpsertSSHTarget(context.Background(), saved); err != nil {
		t.Fatalf("enable file operations update error = %v", err)
	}
	updated, err := store.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("load enabled target: %v", err)
	}
	if !updated.AllowFileOperations {
		t.Fatal("enabled file operations update was not persisted")
	}
	if updated.Revision != initialRevision+1 {
		t.Fatalf("file operations update revision = %d, want %d", updated.Revision, initialRevision+1)
	}
}

func TestValidatedSSHConfigurationPersistsFileOperationsCapability(t *testing.T) {
	store, vault := openSSHConfigurationTestVault(t)
	current := saveSSHConfigurationTestTarget(t, store, vault, SSHTarget{
		IP:                  "192.0.2.203",
		Mode:                SSHDirect,
		SSHPort:             22,
		LoginUsername:       "ops",
		Enabled:             true,
		AllowFileOperations: true,
	}, []byte("password"), "SHA256:original")

	updated, err := vault.CommitValidatedSSHTargetConfiguration(context.Background(), ValidatedSSHTargetConfiguration{
		Target: SSHTarget{
			IP:                  current.IP,
			Mode:                SSHDirect,
			SSHPort:             current.SSHPort,
			LoginUsername:       current.LoginUsername,
			Enabled:             true,
			AllowFileOperations: false,
		},
		ConfirmedFingerprint: "SHA256:original",
	})
	if err != nil {
		t.Fatalf("commit validated SSH configuration: %v", err)
	}
	if updated.AllowFileOperations {
		t.Fatal("validated configuration re-enabled explicitly disabled file operations")
	}
	saved, err := store.SSHTarget(context.Background(), current.IP)
	if err != nil {
		t.Fatalf("load committed SSH configuration: %v", err)
	}
	if saved.AllowFileOperations {
		t.Fatal("committed file operations capability was not persisted")
	}
}
