package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpenCreatesPrivateDatabaseAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The database is created with the operating system's ordinary default
	// permissions; the application does not rewrite mode bits after creation.
	if !info.Mode().IsRegular() {
		t.Errorf("database is not a regular file: %v", info.Mode())
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query schema migrations: %v", err)
	}
	if count == 0 {
		t.Fatal("schema migrations were not applied")
	}
}

func TestOpenReplacesDatabaseResourceBoundariesWithCommandBlacklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
		INSERT INTO schema_migrations (version, applied_at) VALUES
			(1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0),
			(7, 0), (8, 0), (9, 0), (10, 0), (11, 0);
		CREATE TABLE credentials (id TEXT PRIMARY KEY);
		CREATE TABLE ssh_targets (
			ip TEXT PRIMARY KEY,
			connection_mode TEXT NOT NULL CHECK (connection_mode = 'direct'),
			ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
			login_username TEXT,
			credential_id TEXT REFERENCES credentials(id) ON DELETE RESTRICT,
			database_containers TEXT NOT NULL DEFAULT '[]',
			database_volumes TEXT NOT NULL DEFAULT '[]',
			database_data_paths TEXT NOT NULL DEFAULT '[]',
			description TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			identity_status TEXT NOT NULL DEFAULT 'identity_unconfirmed',
			revision INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		INSERT INTO ssh_targets (
			ip, connection_mode, ssh_port, login_username, credential_id,
			database_containers, database_volumes, database_data_paths,
			description, environment, enabled, identity_status, revision, created_at, updated_at
		) VALUES (
			'192.0.2.54', 'direct', 22, 'ops', NULL,
			'["mysql"]', '["mysql-data"]', '["/var/lib/mysql"]',
			'legacy target', 'production', 1, 'identity_verified', 7, 1, 1
		);`)
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create v11 SSH target state: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	credentialStore, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = credentialStore.Close() })

	rows, err := credentialStore.db.Query("PRAGMA table_info(ssh_targets)")
	if err != nil {
		t.Fatalf("inspect SSH target columns: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan SSH target column: %v", err)
		}
		columns[name] = true
	}
	if !columns["command_blacklist_patterns"] {
		t.Fatal("ssh_targets is missing command_blacklist_patterns")
	}
	for _, name := range []string{"database_containers", "database_volumes", "database_data_paths"} {
		if columns[name] {
			t.Fatalf("obsolete SSH target column %q remains", name)
		}
	}

	target, err := credentialStore.SSHTarget(context.Background(), "192.0.2.54")
	if err != nil {
		t.Fatalf("load migrated SSH target: %v", err)
	}
	if len(target.CommandBlacklistPatterns) != 0 || target.Description != "legacy target" || target.Revision != 7 {
		t.Fatalf("migrated SSH target = %#v", target)
	}

	var migrated bool
	if err := credentialStore.db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 12)").Scan(&migrated); err != nil {
		t.Fatalf("check command blacklist migration: %v", err)
	}
	if !migrated {
		t.Fatal("command blacklist migration was not recorded")
	}
}

func TestOpenRepairsRecordedDatabaseAccountMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
		INSERT INTO schema_migrations (version, applied_at) VALUES (1, 0), (2, 0), (3, 0);
		CREATE TABLE database_instances (
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			engine TEXT NOT NULL,
			default_database TEXT NOT NULL DEFAULT '',
			read_credential_id TEXT,
			write_credential_id TEXT,
			description TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE (host, port)
		);`)
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create partially migrated database: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	credentialStore, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = credentialStore.Close() })

	rows, err := credentialStore.db.Query("PRAGMA table_info(database_instances)")
	if err != nil {
		t.Fatalf("inspect database instance columns: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan database instance column: %v", err)
		}
		columns[name] = true
	}
	for _, name := range []string{"read_username", "write_username", "transport_security"} {
		if !columns[name] {
			t.Errorf("database_instances is missing repaired column %q", name)
		}
	}
	var recorded bool
	if err := credentialStore.db.QueryRow("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 4)").Scan(&recorded); err != nil {
		t.Fatalf("check repair migration: %v", err)
	}
	if !recorded {
		t.Error("repair migration version 4 was not recorded")
	}
}

func TestOpenDropsLegacyAuditQueryRulesAndApprovals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
		INSERT INTO schema_migrations (version, applied_at) VALUES (1, 0), (2, 0), (3, 0), (4, 0), (5, 0);
		CREATE TABLE audit_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_id TEXT, session_id TEXT, target_kind TEXT NOT NULL, target_id TEXT NOT NULL,
			payload TEXT NOT NULL, policy_version TEXT NOT NULL, decision TEXT NOT NULL,
			transport_security TEXT, exit_status INTEGER, affected_rows INTEGER, duration_ms INTEGER,
			output_summary TEXT, created_at INTEGER NOT NULL
		);
		INSERT INTO audit_entries (target_kind, target_id, payload, policy_version, decision, created_at)
		VALUES ('ssh', '192.0.2.10', 'cat /etc/shadow', 'v1', 'rejected', 0);
		CREATE TABLE ssh_query_rules (command TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
		INSERT INTO ssh_query_rules (command, created_at, updated_at) VALUES ('nvidia-smi', 0, 0);
		CREATE TABLE approval_requests (id TEXT PRIMARY KEY);
		INSERT INTO approval_requests (id) VALUES ('legacy-approval');`)
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create legacy state: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	credentialStore, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	var exists bool
	if err := credentialStore.db.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ssh_query_rules')").Scan(&exists); err != nil {
		t.Fatalf("check SSH query rules table: %v", err)
	}
	if exists {
		t.Fatal("legacy SSH query rules table remains")
	}
	if err := credentialStore.db.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'approval_requests')").Scan(&exists); err != nil {
		t.Fatalf("检查旧审批表失败：%v", err)
	}
	if exists {
		t.Fatal("旧审批表仍然存在")
	}
	if err := credentialStore.db.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_entries')").Scan(&exists); err != nil {
		t.Fatalf("check audit table: %v", err)
	}
	if exists {
		t.Fatal("legacy audit table remains")
	}
}

func TestTargetUniquenessRules(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if err := store.AddSSHTarget(ctx, SSHTarget{IP: "10.0.0.10", Mode: SSHDirect}); err != nil {
		t.Fatalf("add SSH target: %v", err)
	}
	if err := store.AddSSHTarget(ctx, SSHTarget{IP: "10.0.0.10", Mode: SSHDirect}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate SSH IP error = %v, want ErrConflict", err)
	}

	first := DatabaseInstance{Host: "10.0.0.10", Port: 3306, Engine: EngineMySQL}
	if err := store.AddDatabaseInstance(ctx, first); err != nil {
		t.Fatalf("add database instance: %v", err)
	}
	if err := store.AddDatabaseInstance(ctx, DatabaseInstance{Host: "10.0.0.10", Port: 5432, Engine: EnginePostgreSQL}); err != nil {
		t.Fatalf("add same host with different port: %v", err)
	}
	if err := store.AddDatabaseInstance(ctx, first); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate database address error = %v, want ErrConflict", err)
	}
}

func TestTargetValidationRejectsUnsupportedValues(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if err := store.AddSSHTarget(ctx, SSHTarget{IP: "not-an-ip", Mode: SSHDirect}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("invalid SSH target error = %v, want ErrInvalidTarget", err)
	}
	if err := store.AddDatabaseInstance(ctx, DatabaseInstance{Host: "10.0.0.11", Port: 0, Engine: EngineMySQL}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("invalid database port error = %v, want ErrInvalidTarget", err)
	}
	if err := store.AddDatabaseInstance(ctx, DatabaseInstance{Host: "10.0.0.11", Port: 3306, Engine: "oracle"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("unsupported engine error = %v, want ErrInvalidTarget", err)
	}
}

func TestConcurrentDuplicateSSHTargetHasSingleWinner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	var successes int
	var conflicts int
	var mu sync.Mutex
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := store.AddSSHTarget(ctx, SSHTarget{IP: "10.0.0.20", Mode: SSHDirect})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Errorf("AddSSHTarget() error = %v", err)
			}
		}()
	}
	group.Wait()

	if successes != 1 || conflicts != 7 {
		t.Errorf("successes = %d, conflicts = %d, want 1 and 7", successes, conflicts)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
