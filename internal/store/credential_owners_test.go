package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssh-mcp/internal/secret"
)

func TestVaultTargetCredentialMigrationRollsBackOnFailure(t *testing.T) {
	testCases := []struct {
		name    string
		prepare func(*testing.T, *Store)
	}{
		{
			name: "解密失败",
			prepare: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec("UPDATE credentials SET ciphertext = X'00' WHERE id = 'legacy-shared'"); err != nil {
					t.Fatalf("损坏旧凭据密文失败：%v", err)
				}
			},
		},
		{
			name: "写入失败",
			prepare: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				if _, err := credentialStore.db.Exec(`
					CREATE TRIGGER reject_migrated_credential_insert
					BEFORE INSERT ON credentials
					WHEN NEW.id LIKE 'credential-%'
					BEGIN
						SELECT RAISE(ABORT, 'injected credential migration write failure');
					END;`); err != nil {
					t.Fatalf("注入凭据写入失败失败：%v", err)
				}
			},
		},
		{
			name: "提交失败",
			prepare: func(t *testing.T, credentialStore *Store) {
				t.Helper()
				credentialStore.credentialMigrationCommit = func(*sql.Tx) error {
					return errors.New("injected credential migration commit failure")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			credentialStore, masterPassword := legacyCredentialReferenceStore(t)
			testCase.prepare(t, credentialStore)
			before := targetCredentialMigrationStateSnapshot(t, credentialStore)

			vault, err := credentialStore.Unlock(context.Background(), masterPassword)
			if err != nil {
				t.Fatalf("解锁旧凭据库失败：%v", err)
			}
			defer vault.Lock()
			err = vault.MigrateTargetCredentialOwners(context.Background())
			if !errors.Is(err, ErrCredentialMigrationFailed) {
				t.Fatalf("迁移错误 = %v，期望 ErrCredentialMigrationFailed", err)
			}
			if strings.Contains(err.Error(), legacyMigrationPassword) {
				t.Fatal("迁移错误泄露了明文凭据")
			}
			after := targetCredentialMigrationStateSnapshot(t, credentialStore)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("失败迁移改变了持久化状态：迁移前 %#v，迁移后 %#v", before, after)
			}
		})
	}
}

func TestVaultTargetCredentialMigrationRetriesAfterWriteFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "state.db")
	credentialStore, masterPassword := legacyCredentialReferenceStoreAtPath(t, databasePath)
	if _, err := credentialStore.db.Exec(`
		CREATE TRIGGER reject_migrated_credential_insert
		BEFORE INSERT ON credentials
		WHEN NEW.id LIKE 'credential-%'
		BEGIN
			SELECT RAISE(ABORT, 'injected credential migration write failure');
		END;`); err != nil {
		t.Fatalf("注入凭据写入失败失败：%v", err)
	}
	vault, err := credentialStore.Unlock(context.Background(), masterPassword)
	if err != nil {
		t.Fatalf("解锁旧凭据库失败：%v", err)
	}
	defer vault.Lock()
	before := targetCredentialMigrationStateSnapshot(t, credentialStore)
	if err := vault.MigrateTargetCredentialOwners(context.Background()); !errors.Is(err, ErrCredentialMigrationFailed) {
		t.Fatalf("首次迁移错误 = %v，期望 ErrCredentialMigrationFailed", err)
	}
	if afterFailure := targetCredentialMigrationStateSnapshot(t, credentialStore); !reflect.DeepEqual(afterFailure, before) {
		t.Fatalf("失败迁移改变了持久化状态：迁移前 %#v，迁移后 %#v", before, afterFailure)
	}
	vault.Lock()
	if err := credentialStore.Close(); err != nil {
		t.Fatalf("关闭故障注入后的凭据库失败：%v", err)
	}

	reopenedStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("重新打开故障注入后的凭据库失败：%v", err)
	}
	defer func() { _ = reopenedStore.Close() }()
	if _, err := reopenedStore.db.Exec("DROP TRIGGER reject_migrated_credential_insert"); err != nil {
		t.Fatalf("移除凭据写入故障注入失败：%v", err)
	}
	reopenedVault, err := reopenedStore.Unlock(context.Background(), masterPassword)
	if err != nil {
		t.Fatalf("重新解锁凭据库失败：%v", err)
	}
	defer reopenedVault.Lock()
	if err := reopenedVault.MigrateTargetCredentialOwners(context.Background()); err != nil {
		t.Fatalf("重试迁移失败：%v", err)
	}
	afterSuccess := targetCredentialMigrationStateSnapshot(t, reopenedStore)
	if len(afterSuccess.Credentials) != 5 || afterSuccess.OwnerCount != 4 {
		t.Fatalf("重试迁移后的凭据归属不完整：%#v", afterSuccess)
	}
	if err := reopenedVault.MigrateTargetCredentialOwners(context.Background()); err != nil {
		t.Fatalf("幂等迁移失败：%v", err)
	}
	if afterRetry := targetCredentialMigrationStateSnapshot(t, reopenedStore); !reflect.DeepEqual(afterRetry, afterSuccess) {
		t.Fatalf("幂等迁移改变了状态：首次成功 %#v，重复迁移 %#v", afterSuccess, afterRetry)
	}
}

func TestStoreRejectsCrossOwnerCredentialReuse(t *testing.T) {
	credentialStore := openTestStore(t)
	ctx := context.Background()
	vault, err := credentialStore.Initialize(ctx, []byte("owner-test-master-password"))
	if err != nil {
		t.Fatalf("初始化凭据库失败：%v", err)
	}
	defer vault.Lock()
	if err := vault.PutCredential(ctx, "ssh-owned", "test", []byte("first-password")); err != nil {
		t.Fatalf("写入 SSH 凭据失败：%v", err)
	}
	if err := credentialStore.UpsertSSHTarget(ctx, SSHTarget{
		IP: "192.0.2.70", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-owned", Enabled: true,
	}); err != nil {
		t.Fatalf("写入第一个 SSH 登记目标失败：%v", err)
	}
	if err := credentialStore.UpsertSSHTarget(ctx, SSHTarget{
		IP: "192.0.2.71", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-owned", Enabled: true,
	}); !errors.Is(err, ErrCredentialOwnerConflict) {
		t.Fatalf("复用 SSH 凭据错误 = %v，期望 ErrCredentialOwnerConflict", err)
	}
	if err := credentialStore.UpsertDatabaseInstance(ctx, DatabaseInstance{
		Host: "192.0.2.72", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app", ReadCredentialID: "ssh-owned", TransportSecurity: TransportTLSUnverified, Enabled: true,
	}); !errors.Is(err, ErrCredentialOwnerConflict) {
		t.Fatalf("跨协议复用凭据错误 = %v，期望 ErrCredentialOwnerConflict", err)
	}
	if err := vault.PutCredential(ctx, "database-shared", "test", []byte("second-password")); err != nil {
		t.Fatalf("写入数据库凭据失败：%v", err)
	}
	if err := credentialStore.UpsertDatabaseInstance(ctx, DatabaseInstance{
		Host: "192.0.2.73", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "database-shared",
		WriteUsername: "app_write", WriteCredentialID: "database-shared",
		TransportSecurity: TransportTLSUnverified, Enabled: true,
	}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("读写身份复用凭据错误 = %v，期望 ErrInvalidTarget", err)
	}
	if err := vault.PutCredential(ctx, "ssh-owned", "test", []byte("replacement-password")); !errors.Is(err, ErrCredentialOwnerConflict) {
		t.Fatalf("覆盖已归属凭据错误 = %v，期望 ErrCredentialOwnerConflict", err)
	}
	credential, err := vault.Credential(ctx, "ssh-owned")
	if err != nil {
		t.Fatalf("读取原 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(credential)
	if !bytes.Equal(credential, []byte("first-password")) {
		t.Fatal("拒绝跨归属复用后原 SSH 凭据被改写")
	}
}

const legacyMigrationPassword = "legacy-migration-sentinel"

func legacyCredentialReferenceStore(t *testing.T) (*Store, []byte) {
	t.Helper()
	return legacyCredentialReferenceStoreAtPath(t, filepath.Join(t.TempDir(), "state.db"))
}

func legacyCredentialReferenceStoreAtPath(t *testing.T, databasePath string) (*Store, []byte) {
	t.Helper()
	credentialStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("打开旧凭据库失败：%v", err)
	}
	t.Cleanup(func() { _ = credentialStore.Close() })
	masterPassword := []byte("legacy-migration-master-password")
	t.Cleanup(func() { secret.Zero(masterPassword) })
	vault, err := credentialStore.Initialize(context.Background(), masterPassword)
	if err != nil {
		t.Fatalf("初始化旧凭据库失败：%v", err)
	}
	if err := vault.PutCredential(context.Background(), "legacy-shared", "legacy", []byte(legacyMigrationPassword)); err != nil {
		vault.Lock()
		t.Fatalf("写入旧共享凭据失败：%v", err)
	}
	vault.Lock()
	if _, err := credentialStore.db.Exec(`
		INSERT INTO ssh_targets (
			ip, connection_mode, ssh_port, login_username, credential_id,
			description, environment, enabled, created_at, updated_at
		) VALUES
			('192.0.2.60', 'direct', 22, 'ops', 'legacy-shared', '', '', 1, 0, 0),
			('192.0.2.61', 'direct', 22, 'deploy', 'legacy-shared', '', '', 1, 0, 0);
		INSERT INTO database_instances (
			host, port, engine, default_database, read_username, write_username,
			read_credential_id, write_credential_id, description, environment,
			transport_security, transport_policy, tls_ca_path, enabled, created_at, updated_at
		) VALUES (
			'192.0.2.62', 5432, 'postgresql', 'app', 'app', 'app',
			'legacy-shared', 'legacy-shared', '', '',
			'tls_unverified', 'legacy_plaintext', '', 1, 0, 0
		);`); err != nil {
		t.Fatalf("写入旧版共享引用失败：%v", err)
	}
	return credentialStore, masterPassword
}

type targetCredentialMigrationState struct {
	SSH           []string
	DatabaseRead  []string
	DatabaseWrite []string
	Credentials   map[string][]byte
	OwnerCount    int
}

func targetCredentialMigrationStateSnapshot(t *testing.T, credentialStore *Store) targetCredentialMigrationState {
	t.Helper()
	state := targetCredentialMigrationState{Credentials: make(map[string][]byte)}
	state.SSH = targetCredentialReferenceSnapshot(t, credentialStore, "SELECT ip, credential_id FROM ssh_targets ORDER BY ip")
	state.DatabaseRead = targetCredentialReferenceSnapshot(t, credentialStore, "SELECT host || ':' || port, read_credential_id FROM database_instances ORDER BY host, port")
	state.DatabaseWrite = targetCredentialReferenceSnapshot(t, credentialStore, "SELECT host || ':' || port, write_credential_id FROM database_instances ORDER BY host, port")
	rows, err := credentialStore.db.Query("SELECT id, ciphertext FROM credentials ORDER BY id")
	if err != nil {
		t.Fatalf("读取凭据快照失败：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ciphertext []byte
		if err := rows.Scan(&id, &ciphertext); err != nil {
			t.Fatalf("读取凭据密文快照失败：%v", err)
		}
		state.Credentials[id] = bytes.Clone(ciphertext)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历凭据快照失败：%v", err)
	}
	if err := credentialStore.db.QueryRow("SELECT COUNT(*) FROM credential_owners").Scan(&state.OwnerCount); err != nil {
		t.Fatalf("读取凭据归属快照失败：%v", err)
	}
	return state
}

func targetCredentialReferenceSnapshot(t *testing.T, credentialStore *Store, query string) []string {
	t.Helper()
	rows, err := credentialStore.db.Query(query)
	if err != nil {
		t.Fatalf("读取登记目标凭据引用失败：%v", err)
	}
	defer rows.Close()
	var references []string
	for rows.Next() {
		var target, credentialID string
		if err := rows.Scan(&target, &credentialID); err != nil {
			t.Fatalf("读取登记目标凭据引用行失败：%v", err)
		}
		references = append(references, fmt.Sprintf("%s=%s", target, credentialID))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历登记目标凭据引用失败：%v", err)
	}
	return references
}
