package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/secret"
	"ssh-mcp/internal/session"
	"ssh-mcp/internal/sshservice"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"

	"github.com/go-sql-driver/mysql"
)

func TestServiceUnlockMigratesLegacyCredentialReferences(t *testing.T) {
	t.Parallel()

	const masterPassword = "legacy-master-password"
	const password = "迁移哨兵密码"
	path := filepath.Join(t.TempDir(), "state.db")
	prepareLegacyCredentialReferenceState(t, path, masterPassword, password)

	credentialStore, err := store.Open(path)
	if err != nil {
		t.Fatalf("打开旧凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	manager := session.NewManager(credentialStore)
	service := NewService(credentialStore, manager)

	result := callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: masterPassword})
	if result.Created || !result.Unlocked {
		t.Fatalf("旧凭据库解锁结果不正确：%#v", result)
	}
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.SSH) != 2 || len(targets.Databases) != 1 {
		t.Fatalf("迁移后的登记目标数量不正确：%#v", targets)
	}

	credentialIDs := []string{
		targets.SSH[0].CredentialID,
		targets.SSH[1].CredentialID,
		targets.Databases[0].ReadCredentialID,
		targets.Databases[0].WriteCredentialID,
	}
	if !allDistinct(credentialIDs) {
		t.Fatalf("共享凭据未拆分为独立归属：%#v", credentialIDs)
	}

	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("迁移后未取得已解锁凭据库：%v", err)
	}
	for _, id := range credentialIDs {
		credential, err := vault.Credential(context.Background(), id)
		if err != nil {
			t.Fatalf("读取迁移后的凭据失败：%v", err)
		}
		if !bytes.Equal(credential, []byte(password)) {
			secret.Zero(credential)
			t.Fatal("迁移后的凭据不能使用原密码")
		}
		secret.Zero(credential)
	}

	callService[struct{}](t, service, "lock", nil)
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: masterPassword})
	again := callService[TargetsResult](t, service, "targets.list", nil)
	againIDs := []string{
		again.SSH[0].CredentialID,
		again.SSH[1].CredentialID,
		again.Databases[0].ReadCredentialID,
		again.Databases[0].WriteCredentialID,
	}
	if !slices.Equal(credentialIDs, againIDs) {
		t.Fatalf("重复解锁改变了已迁移凭据：%#v", againIDs)
	}

	encoded, err := json.Marshal(struct {
		Result  UnlockResult  `json:"result"`
		Targets TargetsResult `json:"targets"`
	}{Result: result, Targets: targets})
	if err != nil {
		t.Fatalf("序列化控制结果失败：%v", err)
	}
	if bytes.Contains(encoded, []byte(password)) {
		t.Fatal("控制结果泄露了迁移凭据")
	}
}

func TestServiceUnlockFailsClosedWhenLegacyCredentialMigrationFails(t *testing.T) {
	t.Parallel()

	const masterPassword = "legacy-master-password"
	const password = "迁移失败哨兵密码"
	path := filepath.Join(t.TempDir(), "state.db")
	prepareLegacyCredentialReferenceState(t, path, masterPassword, password)
	legacy, err := sql.Open("sqlite", path+"?_pragma=foreign_keys%3don")
	if err != nil {
		t.Fatalf("打开旧数据库状态失败：%v", err)
	}
	if _, err := legacy.Exec("UPDATE credentials SET ciphertext = X'00' WHERE id = 'legacy-shared'"); err != nil {
		_ = legacy.Close()
		t.Fatalf("损坏旧凭据密文失败：%v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧数据库状态失败：%v", err)
	}

	credentialStore, err := store.Open(path)
	if err != nil {
		t.Fatalf("打开旧凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	manager := session.NewManager(credentialStore)
	service := NewService(credentialStore, manager)
	params, err := json.Marshal(UnlockParams{MasterPassword: masterPassword})
	if err != nil {
		t.Fatalf("序列化解锁参数失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "unlock", params); !errors.Is(err, store.ErrCredentialMigrationFailed) {
		t.Fatalf("解锁错误 = %v，期望 ErrCredentialMigrationFailed", err)
	} else if strings.Contains(err.Error(), password) {
		t.Fatal("解锁错误泄露了迁移凭据")
	}
	if manager.IsUnlocked() {
		t.Fatal("迁移失败后会话仍处于解锁状态")
	}
	status := callService[Status](t, service, "status", nil)
	if status.Unlocked {
		t.Fatalf("迁移失败后的控制状态不正确：%#v", status)
	}
}

func TestServiceUnlockMigratesRestoredLegacyBackup(t *testing.T) {
	t.Parallel()

	const masterPassword = "legacy-backup-master-password"
	const password = "旧备份迁移哨兵密码"
	base := t.TempDir()
	sourcePath := filepath.Join(base, "source.db")
	prepareLegacyCredentialReferenceState(t, sourcePath, masterPassword, password)
	source, err := store.Open(sourcePath)
	if err != nil {
		t.Fatalf("打开旧备份源库失败：%v", err)
	}
	backupPath := filepath.Join(base, "legacy.sshmcp")
	if err := source.CreateBackup(context.Background(), []byte(masterPassword), backupPath); err != nil {
		_ = source.Close()
		t.Fatalf("创建旧备份失败：%v", err)
	}
	sourceTargets, err := source.ListSSHTargets(context.Background())
	if err != nil {
		_ = source.Close()
		t.Fatalf("读取旧备份源目标失败：%v", err)
	}
	if len(sourceTargets) != 2 || sourceTargets[0].CredentialID != "legacy-shared" || sourceTargets[1].CredentialID != "legacy-shared" {
		_ = source.Close()
		t.Fatalf("创建备份意外迁移了源库：%#v", sourceTargets)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("关闭旧备份源库失败：%v", err)
	}

	restoredPath := filepath.Join(base, "restored.db")
	if err := store.RestoreBackup(context.Background(), []byte(masterPassword), backupPath, restoredPath); err != nil {
		t.Fatalf("恢复旧备份失败：%v", err)
	}
	restored, err := store.Open(restoredPath)
	if err != nil {
		t.Fatalf("打开恢复的旧备份失败：%v", err)
	}
	defer restored.Close()
	manager := session.NewManager(restored)
	service := NewService(restored, manager)
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: masterPassword})
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.SSH) != 2 || len(targets.Databases) != 1 {
		t.Fatalf("恢复备份后的登记目标数量不正确：%#v", targets)
	}
	if !allDistinct([]string{
		targets.SSH[0].CredentialID,
		targets.SSH[1].CredentialID,
		targets.Databases[0].ReadCredentialID,
		targets.Databases[0].WriteCredentialID,
	}) {
		t.Fatalf("恢复旧备份后首次解锁未拆分共享凭据：%#v", targets)
	}
	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("恢复旧备份迁移后未取得已解锁凭据库：%v", err)
	}
	for _, credentialID := range []string{
		targets.SSH[0].CredentialID,
		targets.SSH[1].CredentialID,
		targets.Databases[0].ReadCredentialID,
		targets.Databases[0].WriteCredentialID,
	} {
		credential, err := vault.Credential(context.Background(), credentialID)
		if err != nil {
			t.Fatalf("读取恢复备份迁移后的凭据失败：%v", err)
		}
		if !bytes.Equal(credential, []byte(password)) {
			secret.Zero(credential)
			t.Fatal("恢复备份迁移后的凭据不能使用原密码")
		}
		secret.Zero(credential)
	}
}

func TestServiceRejectsUnlockedNewTargetsWithoutPasswords(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	service := NewService(credentialStore, session.NewManager(credentialStore))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	sshParams, err := json.Marshal(UpsertSSHTargetParams{Target: store.SSHTarget{
		IP: "192.0.2.41", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "caller-provided", Enabled: true,
	}})
	if err != nil {
		t.Fatalf("序列化无密码 SSH 新目标失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", sshParams); !errors.Is(err, ipc.ErrInvalidRequest) {
		t.Fatalf("无密码 SSH 新目标错误 = %v，期望 ipc.ErrInvalidRequest", err)
	}

	databaseParams, err := json.Marshal(UpsertDatabaseInstanceParams{Instance: store.DatabaseInstance{
		Host: "192.0.2.42", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app", ReadCredentialID: "caller-provided",
		TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}})
	if err != nil {
		t.Fatalf("序列化无密码数据库新目标失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_database", databaseParams); !errors.Is(err, ipc.ErrInvalidRequest) {
		t.Fatalf("无密码数据库新目标错误 = %v，期望 ipc.ErrInvalidRequest", err)
	}
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.SSH) != 0 || len(targets.Databases) != 0 {
		t.Fatalf("无密码新目标仍被保存：%#v", targets)
	}
}

func TestDecodeUpsertSSHTargetParamsTracksFileCapabilityPresence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		params string
		set    bool
		value  bool
	}{
		{
			name:   "omitted uses compatibility default",
			params: `{"target":{"IP":"192.0.2.250","Mode":"direct","LoginUsername":"ops"}}`,
			set:    false,
			value:  false,
		},
		{
			name:   "explicit false remains authoritative",
			params: `{"target":{"IP":"192.0.2.250","Mode":"direct","LoginUsername":"ops","AllowFileOperations":false}}`,
			set:    true,
			value:  false,
		},
		{
			name:   "explicit true remains enabled",
			params: `{"target":{"IP":"192.0.2.250","Mode":"direct","LoginUsername":"ops","AllowFileOperations":true}}`,
			set:    true,
			value:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, set, err := decodeUpsertSSHTargetParams(json.RawMessage(tc.params))
			if err != nil {
				t.Fatalf("decodeUpsertSSHTargetParams() error = %v", err)
			}
			if set != tc.set || input.Target.AllowFileOperations != tc.value {
				t.Fatalf("decoded capability = %v, present = %v; want %v, %v", input.Target.AllowFileOperations, set, tc.value, tc.set)
			}
		})
	}
}

func TestServiceAllowsSameDatabaseLoginWithSeparateReadAndWriteCredentials(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	manager := session.NewManager(credentialStore)
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	service := NewService(credentialStore, manager, WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.40", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "root", WriteUsername: "root",
		ReadCredentialID: "requested-shared", WriteCredentialID: "requested-shared",
		TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "same-password", WritePassword: "same-password",
	})
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.Databases) != 1 {
		t.Fatalf("数据库登记目标数量不正确：%#v", targets)
	}
	saved := targets.Databases[0]
	if saved.ReadUsername != "root" || saved.WriteUsername != "root" {
		t.Fatalf("同名读写账号未保存：%#v", saved)
	}
	if saved.ReadCredentialID == "" || saved.WriteCredentialID == "" || saved.ReadCredentialID == saved.WriteCredentialID ||
		saved.ReadCredentialID == "requested-shared" || saved.WriteCredentialID == "requested-shared" {
		t.Fatalf("数据库读写凭据未按认证身份隔离：%#v", saved)
	}
	if len(transport.tested) != 2 {
		t.Fatalf("候选数据库读写身份测试次数 = %d，期望 2", len(transport.tested))
	}
	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("读取已解锁凭据库失败：%v", err)
	}
	for _, id := range []string{saved.ReadCredentialID, saved.WriteCredentialID} {
		credential, err := vault.Credential(context.Background(), id)
		if err != nil {
			t.Fatalf("读取数据库凭据失败：%v", err)
		}
		if !bytes.Equal(credential, []byte("same-password")) {
			secret.Zero(credential)
			t.Fatal("数据库读写凭据未保留相同明文密码")
		}
		secret.Zero(credential)
	}

	hijackAttempt := saved
	hijackAttempt.ReadCredentialID = saved.WriteCredentialID
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{Instance: hijackAttempt})
	afterHijackAttempt := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	if afterHijackAttempt.ReadCredentialID != saved.ReadCredentialID || afterHijackAttempt.WriteCredentialID != saved.WriteCredentialID {
		t.Fatalf("调用方篡改数据库凭据 ID 改变了已保存归属：%#v", afterHijackAttempt)
	}

	hijackAttempt.WriteCredentialID = saved.ReadCredentialID
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: hijackAttempt, WritePassword: "rotated-write-password",
	})
	updated := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	readCredential, err := vault.Credential(context.Background(), updated.ReadCredentialID)
	if err != nil {
		t.Fatalf("读取轮换后的只读凭据失败：%v", err)
	}
	defer secret.Zero(readCredential)
	if !bytes.Equal(readCredential, []byte("same-password")) {
		t.Fatal("轮换可写凭据影响了只读身份")
	}
	writeCredential, err := vault.Credential(context.Background(), updated.WriteCredentialID)
	if err != nil {
		t.Fatalf("读取轮换后的可写凭据失败：%v", err)
	}
	defer secret.Zero(writeCredential)
	if !bytes.Equal(writeCredential, []byte("rotated-write-password")) {
		t.Fatal("可写身份凭据未完成轮换")
	}
}

func TestServiceAllowsSameDatabaseLoginToReuseReadCredential(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	manager := session.NewManager(credentialStore)
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	service := NewService(credentialStore, manager, WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: store.DatabaseInstance{
			Host: "192.0.2.49", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
			ReadUsername: "root", WriteUsername: "root", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
		},
		ReadPassword: "same-password",
	})

	saved := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	if saved.ReadUsername != "root" || saved.WriteUsername != "root" || saved.ReadCredentialID == "" || saved.WriteCredentialID != "" {
		t.Fatalf("same-account configuration = %#v", saved)
	}
	if len(transport.tested) != 2 {
		t.Fatalf("candidate database tests = %d, want 2", len(transport.tested))
	}
	if transport.tested[0].Username != "root" || transport.tested[1].Username != "root" ||
		!bytes.Equal(transport.tested[0].Password, transport.tested[1].Password) {
		t.Fatalf("same-account candidate endpoints = %#v", transport.tested)
	}
}

func TestServiceRejectsChangedDatabaseIdentityWithoutReplacementCredential(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.43", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "read-password", WritePassword: "write-password",
	})
	saved := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	remoteTests := len(transport.tested)

	testCases := []struct {
		name     string
		instance store.DatabaseInstance
	}{
		{name: "只读身份", instance: func() store.DatabaseInstance {
			updated := saved
			updated.ReadUsername = "next_read"
			return updated
		}()},
		{name: "可写身份", instance: func() store.DatabaseInstance {
			updated := saved
			updated.WriteUsername = "next_write"
			return updated
		}()},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params, err := json.Marshal(UpsertDatabaseInstanceParams{Instance: testCase.instance})
			if err != nil {
				t.Fatalf("序列化变更后的数据库身份失败：%v", err)
			}
			if _, err := service.Handle(context.Background(), "target.upsert_database", params); !errors.Is(err, ipc.ErrInvalidRequest) {
				t.Fatalf("未提供新密码的身份变更错误 = %v，期望 ipc.ErrInvalidRequest", err)
			}
			if len(transport.tested) != remoteTests {
				t.Fatalf("无效身份变更触发了远端数据库测试：%#v", transport.tested)
			}
			current := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
			if current != saved {
				t.Fatalf("无效身份变更修改了数据库登记目标：%#v", current)
			}
		})
	}
}

func prepareLegacyCredentialReferenceState(t *testing.T, path, masterPassword, password string) {
	t.Helper()
	ctx := context.Background()
	credentialStore, err := store.Open(path)
	if err != nil {
		t.Fatalf("创建旧凭据库失败：%v", err)
	}
	vault, err := credentialStore.Initialize(ctx, []byte(masterPassword))
	if err != nil {
		_ = credentialStore.Close()
		t.Fatalf("初始化旧凭据库失败：%v", err)
	}
	if err := vault.PutCredential(ctx, "legacy-shared", "legacy", []byte(password)); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("写入旧共享凭据失败：%v", err)
	}
	vault.Lock()
	if err := credentialStore.Close(); err != nil {
		t.Fatalf("关闭旧凭据库失败：%v", err)
	}

	legacy, err := sql.Open("sqlite", path+"?_pragma=foreign_keys%3don")
	if err != nil {
		t.Fatalf("打开旧数据库状态失败：%v", err)
	}
	defer legacy.Close()
	if _, err := legacy.Exec(`
		INSERT INTO ssh_targets (
			ip, connection_mode, ssh_port, login_username, credential_id,
			description, environment, enabled, created_at, updated_at
		) VALUES
			('192.0.2.30', 'direct', 22, 'ops', 'legacy-shared', '', '', 1, 0, 0),
			('192.0.2.31', 'direct', 22, 'deploy', 'legacy-shared', '', '', 1, 0, 0);
		INSERT INTO database_instances (
			host, port, engine, default_database, read_username, write_username,
			read_credential_id, write_credential_id, description, environment,
			transport_security, transport_policy, tls_ca_path, enabled, created_at, updated_at
		) VALUES (
			'192.0.2.32', 5432, 'postgresql', 'app', 'app', 'app',
			'legacy-shared', 'legacy-shared', '', '',
			'tls_unverified', 'legacy_plaintext', '', 1, 0, 0
		);`); err != nil {
		t.Fatalf("写入旧版共享引用失败：%v", err)
	}
}

func allDistinct(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func TestServiceUnlocksManagesTargetsAndNeverReturnsPasswords(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}))

	status := callService[Status](t, service, "status", nil)
	if status.Initialized || status.Unlocked {
		t.Fatalf("initial status = %#v", status)
	}

	unlock := callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	if !unlock.Created || !unlock.Unlocked {
		t.Fatalf("unlock result = %#v", unlock)
	}

	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(store.SSHTarget{
		IP:            "192.0.2.20",
		Mode:          store.SSHDirect,
		LoginUsername: "ops",
		CredentialID:  "ssh-192.0.2.20",
		Enabled:       true,
	}, "only-in-local-vault"))
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.SSH) != 1 || targets.SSH[0].CredentialID == "" || targets.SSH[0].CredentialID == "ssh-192.0.2.20" {
		t.Fatalf("targets = %#v", targets)
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}
	if strings.Contains(string(encoded), "only-in-local-vault") {
		t.Fatalf("target response exposed password: %s", encoded)
	}

	callService[struct{}](t, service, "lock", nil)
	params, _ := json.Marshal(UpsertSSHTargetParams{Target: store.SSHTarget{IP: "192.0.2.21", Mode: store.SSHDirect}})
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("write while locked error = %v, want ErrLocked", err)
	}
}

func TestServiceDeletesUnlockedTargetsAndRevokesAuthorization(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	revoker := &controlTestRevoker{}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(store.SSHTarget{
		IP: "192.0.2.20", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "ssh-delete", Enabled: true,
	}, "ssh-password"))
	callService[struct{}](t, service, "lock", nil)
	lockedParams, _ := json.Marshal(DeleteSSHTargetParams{IP: "192.0.2.20"})
	if _, err := service.Handle(context.Background(), "target.delete_ssh", lockedParams); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("delete while locked error = %v, want ErrLocked", err)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), "192.0.2.20"); err != nil {
		t.Fatalf("target changed while locked: %v", err)
	}

	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	callService[struct{}](t, service, "target.delete_ssh", DeleteSSHTargetParams{IP: "192.0.2.20"})
	if _, err := credentialStore.SSHTarget(context.Background(), "192.0.2.20"); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("SSHTarget() error = %v, want ErrTargetNotFound", err)
	}
	if len(revoker.ssh) != 1 || revoker.ssh[0] != "192.0.2.20" {
		t.Fatalf("SSH revocations = %#v", revoker.ssh)
	}
}

func TestServiceRevokesExistingSSHTargetWhenCredentialUpdatePrecedesInvalidTargetUpdate(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	revoker := &controlTestRevoker{}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{
		IP: "192.0.2.20", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "ssh-update", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "old-password"))
	revoker.clearSSHAuthorizationEvents()

	target.LoginUsername = ""
	params, err := json.Marshal(confirmedSSHUpsert(target, "new-password"))
	if err != nil {
		t.Fatalf("marshal update: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); !errors.Is(err, store.ErrInvalidTarget) {
		t.Fatalf("credential update with invalid target error = %v, want ErrInvalidTarget", err)
	}
	if len(revoker.ssh) != 1 || revoker.ssh[0] != target.IP {
		t.Fatalf("SSH revocations = %#v, want credential update revocation", revoker.ssh)
	}
	if want := []string{target.IP}; !slices.Equal(revoker.sshActivations, want) {
		t.Fatalf("SSH activations = %#v, want %#v", revoker.sshActivations, want)
	}
}

func TestServiceCommitsNewSSHTargetOnlyAfterConfirmedConfigurationValidation(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: "SHA256:candidate"}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	candidate := store.SSHTarget{
		IP: "192.0.2.23", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "caller-value", Enabled: true,
		CommandBlacklistPatterns: []string{"rm /data/.*", "passwd.*"},
	}

	params, err := json.Marshal(UpsertSSHTargetParams{Target: candidate, Password: "candidate-password"})
	if err != nil {
		t.Fatalf("序列化未确认 SSH 配置变更失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("未确认 SSH 配置变更错误 = %v，期望 ErrConfirmationRequired", err)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), candidate.IP); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("未确认 SSH 配置变更已保存目标：%v", err)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), candidate.IP, candidate.SSHPort); !errors.Is(err, store.ErrHostKeyNotFound) {
		t.Fatalf("未确认 SSH 配置变更已保存主机身份：%v", err)
	}

	initial := callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{Target: candidate, Password: "candidate-password"})
	if !initial.RequiresFingerprintConfirmation || initial.Fingerprint != transport.fingerprint {
		t.Fatalf("SSH 配置变更主机身份预览 = %#v", initial)
	}
	confirmed := callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{
		Target: candidate, Password: "candidate-password", ConfirmedFingerprint: initial.Fingerprint,
	})
	if confirmed.RequiresFingerprintConfirmation || confirmed.Fingerprint != transport.fingerprint {
		t.Fatalf("SSH 配置变更主机身份确认 = %#v", confirmed)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), candidate.IP, candidate.SSHPort); !errors.Is(err, store.ErrHostKeyNotFound) {
		t.Fatalf("SSH 配置变更验证阶段已保存主机身份：%v", err)
	}

	callService[struct{}](t, service, "target.upsert_ssh", UpsertSSHTargetParams{
		Target: candidate, Password: "candidate-password", ConfirmedFingerprint: confirmed.Fingerprint,
	})
	saved, err := credentialStore.SSHTarget(context.Background(), candidate.IP)
	if err != nil {
		t.Fatalf("确认 SSH 配置变更后未保存目标：%v", err)
	}
	if saved.CredentialID == "" || saved.CredentialID == candidate.CredentialID {
		t.Fatalf("确认 SSH 配置变更未生成目标专属凭据：%#v", saved)
	}
	if !slices.Equal(saved.CommandBlacklistPatterns, candidate.CommandBlacklistPatterns) {
		t.Fatalf("确认 SSH 配置变更丢失命令黑名单：%#v", saved)
	}
	fingerprint, err := credentialStore.HostKeyFingerprint(context.Background(), candidate.IP, candidate.SSHPort)
	if err != nil || fingerprint != confirmed.Fingerprint {
		t.Fatalf("确认 SSH 配置变更后的主机身份 = %q, %v", fingerprint, err)
	}
}

func TestServiceRejectsInvalidSSHCommandBlacklistBeforeCandidateDispatch(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: "SHA256:candidate"}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	params, err := json.Marshal(SSHTestParams{
		Target: store.SSHTarget{
			IP: "192.0.2.24", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true,
			CommandBlacklistPatterns: []string{"["},
		},
		Password: "candidate-password",
	})
	if err != nil {
		t.Fatalf("marshal invalid SSH target: %v", err)
	}
	if _, err := service.Handle(context.Background(), "ssh.test_target", params); !errors.Is(err, store.ErrInvalidTarget) || !errors.Is(err, ipc.ErrInvalidRequest) {
		t.Fatalf("invalid command blacklist error = %v, want ErrInvalidTarget and ErrInvalidRequest", err)
	}
	if transport.probeCalls != 0 || transport.testCalls != 0 {
		t.Fatalf("invalid command blacklist dispatched candidate validation: %#v", transport)
	}
}

func TestServiceAuditsSSHCandidateValidationLifecycleWithoutSecrets(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	auditor := &controlTestAuditor{}
	transport := &controlFakeSSHTransport{fingerprint: "SHA256:candidate-audit"}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithAuditor(auditor), WithAuditActor(auditlog.Actor{User: "operator", Source: "tui-control"}))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{IP: "192.0.2.83", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}

	pending := callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{Target: target, Password: "candidate-ssh-password"})
	if !pending.RequiresFingerprintConfirmation {
		t.Fatalf("未确认主机身份的候选校验结果 = %#v", pending)
	}
	completed := callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{
		Target: target, Password: "candidate-ssh-password", ConfirmedFingerprint: pending.Fingerprint,
	})
	if completed.RequiresFingerprintConfirmation {
		t.Fatalf("确认主机身份后的候选校验结果 = %#v", completed)
	}

	transport.testErr = errors.New("SSH candidate test failed")
	params, err := json.Marshal(SSHTestParams{Target: target, Password: "candidate-ssh-password", ConfirmedFingerprint: pending.Fingerprint})
	if err != nil {
		t.Fatalf("marshal SSHTestParams: %v", err)
	}
	if _, err := service.Handle(context.Background(), "ssh.test_target", params); err == nil {
		t.Fatal("失败的 SSH 候选校验意外成功")
	}

	events := auditor.Events()
	if len(events) != 6 {
		t.Fatalf("SSH 候选审计事件数 = %d，期望 6：%#v", len(events), events)
	}
	assertCandidateAuditEvent(t, events[0], auditlog.PhaseStarted, "ssh", target.IP, "started")
	assertCandidateAuditEvent(t, events[1], auditlog.PhaseDecision, "ssh", target.IP, "confirmation_required")
	assertCandidateAuditEvent(t, events[2], auditlog.PhaseStarted, "ssh", target.IP, "started")
	assertCandidateAuditEvent(t, events[3], auditlog.PhaseCompleted, "ssh", target.IP, "completed")
	assertCandidateAuditEvent(t, events[4], auditlog.PhaseStarted, "ssh", target.IP, "started")
	assertCandidateAuditEvent(t, events[5], auditlog.PhaseFailed, "ssh", target.IP, "failed")
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	if strings.Contains(string(encoded), "candidate-ssh-password") || strings.Contains(string(encoded), "SSH candidate test failed") {
		t.Fatalf("候选 SSH 审计泄露敏感内容：%s", encoded)
	}
}

func TestServiceAuditsDatabaseCandidateValidationLifecycle(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	auditor := &controlTestAuditor{}
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSVerified, version: dbtransport.DatabaseVersion{Major: 16}}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport), WithAuditor(auditor))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.84", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app", ReadUsername: "reader", Enabled: true,
	}

	result := callService[DatabaseTestResult](t, service, "database.test_target", DatabaseTestParams{Instance: instance, ReadPassword: "candidate-database-password"})
	if result.MajorVersion != 16 || result.VersionStatus != store.DatabaseVersionVerified {
		t.Fatalf("数据库候选校验结果 = %#v", result)
	}
	transport.testErr = errors.New("database candidate test failed")
	params, err := json.Marshal(DatabaseTestParams{Instance: instance, ReadPassword: "candidate-database-password"})
	if err != nil {
		t.Fatalf("marshal DatabaseTestParams: %v", err)
	}
	if _, err := service.Handle(context.Background(), "database.test_target", params); err == nil {
		t.Fatal("失败的数据库候选校验意外成功")
	}

	targetID := "192.0.2.84:5432"
	events := auditor.Events()
	if len(events) != 4 {
		t.Fatalf("数据库候选审计事件数 = %d，期望 4：%#v", len(events), events)
	}
	assertCandidateAuditEvent(t, events[0], auditlog.PhaseStarted, "database", targetID, "started")
	assertCandidateAuditEvent(t, events[1], auditlog.PhaseCompleted, "database", targetID, "completed")
	assertCandidateAuditEvent(t, events[2], auditlog.PhaseStarted, "database", targetID, "started")
	assertCandidateAuditEvent(t, events[3], auditlog.PhaseFailed, "database", targetID, "failed")
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	if strings.Contains(string(encoded), "candidate-database-password") || strings.Contains(string(encoded), "database candidate test failed") {
		t.Fatalf("候选数据库审计泄露敏感内容：%s", encoded)
	}
}

func TestServiceContinuesCandidateValidationWhenStartAuditCannotBeWritten(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	auditor := &controlTestAuditor{failAt: 1, err: errors.New("audit storage unavailable")}
	transport := &controlFakeSSHTransport{fingerprint: controlTestFingerprint}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithAuditor(auditor))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{IP: "192.0.2.85", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	params, err := json.Marshal(confirmedSSHUpsert(target, "candidate-password"))
	if err != nil {
		t.Fatalf("marshal UpsertSSHTargetParams: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); err != nil {
		t.Fatalf("审计开始写入失败时更新目标错误 = %v", err)
	}
	if transport.probeCalls == 0 || transport.testCalls == 0 {
		t.Fatalf("审计失败后没有执行 SSH 候选探测：probe=%d test=%d", transport.probeCalls, transport.testCalls)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), target.IP); err != nil {
		t.Fatalf("审计失败后目标未保存：%v", err)
	}
}

func TestServiceContinuesCandidateSaveWhenCompletionAuditCannotBeWritten(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	auditor := &controlTestAuditor{failAt: 2, err: errors.New("audit storage unavailable")}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithAuditor(auditor))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{IP: "192.0.2.86", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	params, err := json.Marshal(confirmedSSHUpsert(target, "candidate-password"))
	if err != nil {
		t.Fatalf("marshal UpsertSSHTargetParams: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); err != nil {
		t.Fatalf("完成审计写入失败时更新目标错误 = %v", err)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), target.IP); err != nil {
		t.Fatalf("完成审计失败后目标未保存：%v", err)
	}
}

func TestServiceCandidateValidationRespectsLockedDispatchBarrier(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	barrier := newControlTestDispatchBarrier()
	if err := barrier.Lock(context.Background()); err != nil {
		t.Fatalf("Lock() error = %v", err)
	}
	defer barrier.Unlock()
	transport := &controlFakeSSHTransport{fingerprint: controlTestFingerprint}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithDispatchLeaseAcquirer(func() DispatchLease {
		return barrier.Acquire()
	}))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{IP: "192.0.2.87", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	params, err := json.Marshal(confirmedSSHUpsert(target, "candidate-password"))
	if err != nil {
		t.Fatalf("marshal UpsertSSHTargetParams: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); !errors.Is(err, ErrCandidateNotDispatched) {
		t.Fatalf("锁定期间候选校验错误 = %v，期望 ErrCandidateNotDispatched", err)
	}
	if transport.probeCalls != 0 || transport.testCalls != 0 {
		t.Fatalf("锁定期间仍执行候选 SSH 网络验证：probe=%d test=%d", transport.probeCalls, transport.testCalls)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), target.IP); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("锁定期间候选校验仍保存目标：%v", err)
	}
}

func TestCandidateValidationFailuresUseSanitizedIPCCategories(t *testing.T) {
	t.Parallel()

	const secret = "candidate-password-must-not-leave-control"
	cases := []struct {
		name     string
		err      error
		category error
	}{
		{
			name:     "connection",
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: errors.New(secret)},
			category: ipc.ErrCandidateConnectionFailed,
		},
		{
			name:     "authentication",
			err:      &mysql.MySQLError{Number: 1045, Message: secret},
			category: ipc.ErrCandidateAuthenticationFailed,
		},
		{
			name:     "TLS",
			err:      x509.UnknownAuthorityError{},
			category: ipc.ErrCandidateTLSFailed,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			classified := classifyCandidateValidationFailure(test.err)
			if !errors.Is(classified, test.category) {
				t.Fatalf("classified error = %v, want category %v", classified, test.category)
			}
			if strings.Contains(classified.Error(), secret) {
				t.Fatalf("classified error leaked cause: %q", classified.Error())
			}
		})
	}
}

func TestLocalControlErrorsExposeIPCCategories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      error
		category error
	}{
		{name: "locked", err: store.ErrLocked, category: ipc.ErrLocked},
		{name: "invalid target", err: store.ErrInvalidTarget, category: ipc.ErrInvalidRequest},
		{name: "not dispatched", err: ErrCandidateNotDispatched, category: ipc.ErrCandidateNotDispatched},
		{name: "audit write", err: ErrCandidateAuditWriteFailed, category: ipc.ErrCandidateAuditWriteFailed},
		{name: "confirmation", err: ErrConfirmationRequired, category: ipc.ErrConfirmationRequired},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			classified := classifyLocalControlError(test.err)
			if !errors.Is(classified, test.err) || !errors.Is(classified, test.category) {
				t.Fatalf("classified error = %v, want %v and %v", classified, test.err, test.category)
			}
		})
	}
}

func TestServiceCandidateValidationDrainsBeforeGlobalLock(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	barrier := newControlTestDispatchBarrier()
	transport := &blockingControlSSHTransport{
		fingerprint: controlTestFingerprint,
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithDispatchLeaseAcquirer(func() DispatchLease {
		return barrier.Acquire()
	}))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{IP: "192.0.2.88", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	params, err := json.Marshal(confirmedSSHUpsert(target, "candidate-password"))
	if err != nil {
		t.Fatalf("marshal UpsertSSHTargetParams: %v", err)
	}
	validationDone := make(chan error, 1)
	go func() {
		_, handleErr := service.Handle(context.Background(), "target.upsert_ssh", params)
		validationDone <- handleErr
	}()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("候选 SSH 校验未到达远端验证")
	}

	lockDone := make(chan error, 1)
	go func() { lockDone <- barrier.Lock(context.Background()) }()
	select {
	case lockErr := <-lockDone:
		t.Fatalf("全局锁在候选验证未结束前提前返回：%v", lockErr)
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.release)
	select {
	case handleErr := <-validationDone:
		if handleErr != nil {
			t.Fatalf("候选 SSH 校验错误 = %v", handleErr)
		}
	case <-time.After(time.Second):
		t.Fatal("候选 SSH 校验未结束")
	}
	select {
	case lockErr := <-lockDone:
		if lockErr != nil {
			t.Fatalf("全局锁错误 = %v", lockErr)
		}
	case <-time.After(time.Second):
		t.Fatal("全局锁未等待候选验证收束")
	}
}

func TestServiceLeavesNewSSHTargetUnchangedWhenConfigurationConnectivityFails(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: "SHA256:failed-candidate", testErr: errors.New("SSH 配置变更连通性测试失败")}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	candidate := store.SSHTarget{
		IP: "192.0.2.24", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "调用方值", Enabled: true,
	}

	params, err := json.Marshal(UpsertSSHTargetParams{
		Target: candidate, Password: "candidate-password", ConfirmedFingerprint: transport.fingerprint,
	})
	if err != nil {
		t.Fatalf("序列化失败的 SSH 配置变更失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); err == nil {
		t.Fatal("SSH 配置变更连通性失败后登记目标配置意外成功")
	}
	if _, err := credentialStore.SSHTarget(context.Background(), candidate.IP); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("SSH 配置变更连通性失败后保存了 SSH 登记目标：%v", err)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), candidate.IP, candidate.SSHPort); !errors.Is(err, store.ErrHostKeyNotFound) {
		t.Fatalf("SSH 配置变更连通性失败后保存了主机身份：%v", err)
	}
}

func TestServicePreservesExistingSSHTargetWhenConfigurationConnectivityFails(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: controlTestFingerprint}
	revoker := &controlTestRevoker{}
	manager := session.NewManager(credentialStore)
	service := NewService(credentialStore, manager, WithSSHTransport(transport), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	current := store.SSHTarget{
		IP: "192.0.2.25", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "调用方旧值", Enabled: true,
	}
	other := store.SSHTarget{
		IP: "192.0.2.26", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "deploy", CredentialID: "调用方其他值", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(current, "old-password"))
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(other, "other-password"))
	before, err := credentialStore.SSHTarget(context.Background(), current.IP)
	if err != nil {
		t.Fatalf("读取原 SSH 登记目标失败：%v", err)
	}
	otherBefore, err := credentialStore.SSHTarget(context.Background(), other.IP)
	if err != nil {
		t.Fatalf("读取其他 SSH 登记目标失败：%v", err)
	}
	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("取得已解锁凭据库失败：%v", err)
	}
	beforePassword, err := vault.Credential(context.Background(), before.CredentialID)
	if err != nil {
		t.Fatalf("读取原 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(beforePassword)
	revoker.clearSSHAuthorizationEvents()
	transport.testErr = errors.New("SSH 配置变更连通性测试失败")
	candidate := before
	candidate.SSHPort = 2200
	candidate.LoginUsername = "operator"
	candidate.CredentialID = "调用方新值"
	params, err := json.Marshal(confirmedSSHUpsert(candidate, "new-password"))
	if err != nil {
		t.Fatalf("序列化失败的 SSH 配置变更失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", params); err == nil {
		t.Fatal("已有 SSH 登记目标的 SSH 配置变更连通性失败后配置意外成功")
	}
	after, err := credentialStore.SSHTarget(context.Background(), current.IP)
	if err != nil {
		t.Fatalf("读取失败后的 SSH 登记目标失败：%v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("SSH 配置变更连通性失败改变了 SSH 登记目标：提交前 %#v，提交后 %#v", before, after)
	}
	afterPassword, err := vault.Credential(context.Background(), after.CredentialID)
	if err != nil {
		t.Fatalf("读取失败后的 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(afterPassword)
	if !bytes.Equal(afterPassword, beforePassword) {
		t.Fatal("SSH 配置变更连通性失败改变了既有 SSH 凭据")
	}
	fingerprint, err := credentialStore.HostKeyFingerprint(context.Background(), current.IP, before.SSHPort)
	if err != nil || fingerprint != controlTestFingerprint {
		t.Fatalf("SSH 配置变更连通性失败后的既有主机身份 = %q，错误 = %v", fingerprint, err)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), current.IP, candidate.SSHPort); !errors.Is(err, store.ErrHostKeyNotFound) {
		t.Fatalf("SSH 配置变更连通性失败后保存了新端口的主机身份：%v", err)
	}
	otherAfter, err := credentialStore.SSHTarget(context.Background(), other.IP)
	if err != nil || !reflect.DeepEqual(otherAfter, otherBefore) {
		t.Fatalf("SSH 配置变更连通性失败改变了其他 SSH 登记目标：%#v，错误 = %v", otherAfter, err)
	}
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.25", "activate:192.0.2.25")
}

func TestServiceKeepsSSHTargetCredentialsSeparate(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	revoker := &controlTestRevoker{}
	manager := session.NewManager(credentialStore)
	service := NewService(credentialStore, manager, WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	first := store.SSHTarget{
		IP: "192.0.2.20", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "ssh-shared", Enabled: true,
	}
	second := store.SSHTarget{
		IP: "192.0.2.21", Mode: store.SSHDirect, LoginUsername: "deploy", CredentialID: "ssh-shared", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(first, "initial-password"))
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(second, "initial-password"))
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(targets.SSH) != 2 || targets.SSH[0].CredentialID == targets.SSH[1].CredentialID {
		t.Fatalf("SSH 凭据未按登记目标隔离：%#v", targets.SSH)
	}
	firstCredentialID, secondCredentialID := targets.SSH[0].CredentialID, targets.SSH[1].CredentialID
	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("读取已解锁凭据库失败：%v", err)
	}
	firstCredential, err := vault.Credential(context.Background(), targets.SSH[0].CredentialID)
	if err != nil {
		t.Fatalf("读取第一个 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(firstCredential)
	if !bytes.Equal(firstCredential, []byte("initial-password")) {
		t.Fatal("第一个 SSH 凭据未保留初始密码")
	}
	revoker.clearSSHAuthorizationEvents()

	second.CredentialID = firstCredentialID
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(second, ""))
	afterHijackAttempt := callService[TargetsResult](t, service, "targets.list", nil).SSH
	if afterHijackAttempt[0].CredentialID != firstCredentialID || afterHijackAttempt[1].CredentialID != secondCredentialID {
		t.Fatalf("调用方篡改 SSH 凭据 ID 改变了已保存归属：%#v", afterHijackAttempt)
	}
	revoker.clearSSHAuthorizationEvents()

	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(second, "rotated-password"))
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.21", "activate:192.0.2.21")
	updatedTargets := callService[TargetsResult](t, service, "targets.list", nil)
	if updatedTargets.SSH[0].CredentialID != firstCredentialID || updatedTargets.SSH[1].CredentialID == secondCredentialID {
		t.Fatalf("轮换后的 SSH 凭据标识不符合预期：%#v", updatedTargets.SSH)
	}
	if _, err := vault.Credential(context.Background(), secondCredentialID); !errors.Is(err, store.ErrCredentialNotFound) {
		t.Fatalf("轮换后读取旧 SSH 凭据错误 = %v，期望 ErrCredentialNotFound", err)
	}
	firstCredential, err = vault.Credential(context.Background(), updatedTargets.SSH[0].CredentialID)
	if err != nil {
		t.Fatalf("读取轮换后的第一个 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(firstCredential)
	if !bytes.Equal(firstCredential, []byte("initial-password")) {
		t.Fatal("轮换第二个 SSH 凭据影响了第一个登记目标")
	}
	secondCredential, err := vault.Credential(context.Background(), updatedTargets.SSH[1].CredentialID)
	if err != nil {
		t.Fatalf("读取轮换后的第二个 SSH 凭据失败：%v", err)
	}
	defer secret.Zero(secondCredential)
	if !bytes.Equal(secondCredential, []byte("rotated-password")) {
		t.Fatal("第二个 SSH 凭据未完成轮换")
	}
}

func TestServiceActivatesSSHTargetAfterSuccessfulTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: controlTestFingerprint}
	revoker := &controlTestRevoker{}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{
		IP: "192.0.2.20", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-lifecycle", Enabled: true,
	}

	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "ssh-password"))
	assertSSHAuthorizationEvents(t, revoker, "activate:192.0.2.20")
	revoker.clearSSHAuthorizationEvents()

	target.LoginUsername = "deploy"
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, ""))
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.20", "activate:192.0.2.20")
	revoker.clearSSHAuthorizationEvents()

	callService[struct{}](t, service, "target.set_ssh_enabled", SetSSHTargetEnabledParams{IP: target.IP, Enabled: false})
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.20")
	revoker.clearSSHAuthorizationEvents()

	callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{
		Target: target, Password: "ssh-password", ConfirmedFingerprint: controlTestFingerprint,
	})
	assertSSHAuthorizationEvents(t, revoker)
	revoker.clearSSHAuthorizationEvents()

	callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{
		Target: target, Password: "ssh-password",
	})
	assertSSHAuthorizationEvents(t, revoker)

	callService[struct{}](t, service, "target.delete_ssh", DeleteSSHTargetParams{IP: target.IP})
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.20")
}

func TestServiceRestoresSSHTargetAfterFailedTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeSSHTransport{fingerprint: controlTestFingerprint}
	revoker := &controlTestRevoker{}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(transport), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{
		IP: "192.0.2.21", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-lifecycle", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "ssh-password"))
	revoker.clearSSHAuthorizationEvents()

	invalidTarget := target
	invalidTarget.LoginUsername = ""
	invalidParams, err := json.Marshal(confirmedSSHUpsert(invalidTarget, ""))
	if err != nil {
		t.Fatalf("marshal invalid target: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_ssh", invalidParams); !errors.Is(err, store.ErrInvalidTarget) {
		t.Fatalf("invalid target update error = %v, want ErrInvalidTarget", err)
	}
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.21", "activate:192.0.2.21")
	revoker.clearSSHAuthorizationEvents()

	revoker.onSSH = func(ip string) {
		if err := credentialStore.DeleteSSHTarget(context.Background(), ip); err != nil {
			t.Fatalf("DeleteSSHTarget() during revocation error = %v", err)
		}
	}
	setEnabledParams, err := json.Marshal(SetSSHTargetEnabledParams{IP: target.IP, Enabled: false})
	if err != nil {
		t.Fatalf("marshal enabled state: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.set_ssh_enabled", setEnabledParams); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("enabled state update error = %v, want ErrTargetNotFound", err)
	}
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.21", "activate:192.0.2.21")
	revoker.clearSSHAuthorizationEvents()
	revoker.onSSH = nil

	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "ssh-password"))
	revoker.clearSSHAuthorizationEvents()
	revoker.onSSH = func(ip string) {
		if err := credentialStore.DeleteSSHTarget(context.Background(), ip); err != nil {
			t.Fatalf("DeleteSSHTarget() during revocation error = %v", err)
		}
	}
	deleteParams, err := json.Marshal(DeleteSSHTargetParams{IP: target.IP})
	if err != nil {
		t.Fatalf("marshal delete target: %v", err)
	}
	if _, err := service.Handle(context.Background(), "target.delete_ssh", deleteParams); !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("delete target error = %v, want ErrTargetNotFound", err)
	}
	assertSSHAuthorizationEvents(t, revoker, "revoke:192.0.2.21", "activate:192.0.2.21")
	revoker.clearSSHAuthorizationEvents()
	revoker.onSSH = nil

	transport.testErr = errors.New("SSH 配置变更连通性测试失败")
	confirmParams, err := json.Marshal(SSHTestParams{Target: target, Password: "ssh-password", ConfirmedFingerprint: controlTestFingerprint})
	if err != nil {
		t.Fatalf("marshal SSH target test: %v", err)
	}
	if _, err := service.Handle(context.Background(), "ssh.test_target", confirmParams); err == nil {
		t.Fatal("confirmed SSH target test unexpectedly succeeded")
	}
	assertSSHAuthorizationEvents(t, revoker)
}

func TestServiceSerializesConcurrentSSHTargetChanges(t *testing.T) {
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	revoker := newBlockingControlTestRevoker()
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithTargetAuthorizationRevoker(revoker))
	locker := newTrackingSSHTargetLocker()
	service.sshTargetMu = locker
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{
		IP: "192.0.2.22", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "ssh-concurrent", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "ssh-password"))
	revoker.armNextActivation()

	firstTarget := target
	firstTarget.LoginUsername = "deploy"
	firstParams, err := json.Marshal(confirmedSSHUpsert(firstTarget, ""))
	if err != nil {
		t.Fatalf("marshal first update: %v", err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, handleErr := service.Handle(context.Background(), "target.upsert_ssh", firstParams)
		firstDone <- handleErr
	}()
	select {
	case <-revoker.firstActivationBlocked:
	case <-time.After(time.Second):
		t.Fatal("第一次 SSH 目标更新未进入激活阶段")
	}
	defer revoker.releaseFirstActivation()

	secondTarget := target
	secondTarget.LoginUsername = "admin"
	secondParams, err := json.Marshal(confirmedSSHUpsert(secondTarget, ""))
	if err != nil {
		t.Fatalf("marshal second update: %v", err)
	}
	secondDone := make(chan error, 1)
	go func() {
		_, handleErr := service.Handle(context.Background(), "target.upsert_ssh", secondParams)
		secondDone <- handleErr
	}()

	select {
	case <-locker.secondWaiting:
	case <-time.After(time.Second):
		t.Fatal("第二次 SSH 目标更新未等待第一次更新释放锁")
	}
	select {
	case <-revoker.secondRevocation:
		t.Fatal("第一次更新释放前，第二次更新已经撤销了 SSH 授权")
	default:
	}
	select {
	case handleErr := <-secondDone:
		t.Fatalf("第一次更新释放前，第二次更新已经完成：%v", handleErr)
	default:
	}

	revoker.releaseFirstActivation()
	select {
	case handleErr := <-firstDone:
		if handleErr != nil {
			t.Fatalf("first update error = %v", handleErr)
		}
	case <-time.After(time.Second):
		t.Fatal("第一次 SSH 目标更新未完成")
	}
	select {
	case handleErr := <-secondDone:
		if handleErr != nil {
			t.Fatalf("second update error = %v", handleErr)
		}
	case <-time.After(time.Second):
		t.Fatal("第二次 SSH 目标更新未完成")
	}

	if want := []string{
		"activate:192.0.2.22",
		"revoke:192.0.2.22",
		"activate:192.0.2.22",
		"revoke:192.0.2.22",
		"activate:192.0.2.22",
	}; !slices.Equal(revoker.events(), want) {
		t.Fatalf("SSH authorization events = %#v, want %#v", revoker.events(), want)
	}
}

func TestServiceRevokesSSHAuthorityBeforePersistingTargetUpdate(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	var targetAtRevocation store.SSHTarget
	revoker := &controlTestRevoker{onSSH: func(target string) {
		value, lookupErr := credentialStore.SSHTarget(context.Background(), target)
		if lookupErr != nil {
			t.Fatalf("SSHTarget() during revocation error = %v", lookupErr)
		}
		targetAtRevocation = value
	}}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: controlTestFingerprint}), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	target := store.SSHTarget{
		IP: "192.0.2.20", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "ssh-update", Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, "old-password"))

	target.LoginUsername = "deploy"
	callService[struct{}](t, service, "target.upsert_ssh", confirmedSSHUpsert(target, ""))
	if targetAtRevocation.LoginUsername != "ops" || targetAtRevocation.Revision == 0 {
		t.Fatalf("target at revocation = %#v, want pre-update target", targetAtRevocation)
	}
}

func TestServiceProvidesBackupAndDEKRotationMaintenanceActions(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	credentialStore, err := store.Open(filepath.Join(base, "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	service := NewService(credentialStore, session.NewManager(credentialStore))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	backupPath := filepath.Join(base, "backup.enc")
	callService[struct{}](t, service, "backup.create", BackupCreateParams{MasterPassword: "test-master-password", Destination: backupPath})
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup was not created: %v", err)
	}
	restoredPath := filepath.Join(base, "restored.db")
	callService[struct{}](t, service, "backup.restore", BackupRestoreParams{MasterPassword: "test-master-password", Source: backupPath, Destination: restoredPath})
	if _, err := os.Stat(restoredPath); err != nil {
		t.Fatalf("backup was not restored: %v", err)
	}

	params, _ := json.Marshal(RotateDataKeyParams{MasterPassword: "test-master-password", Confirmation: "not-confirmed"})
	if _, err := service.Handle(context.Background(), "keys.rotate", params); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed rotation error = %v, want ErrConfirmationRequired", err)
	}
	callService[struct{}](t, service, "keys.rotate", RotateDataKeyParams{MasterPassword: "test-master-password", Confirmation: "ROTATE"})
}

func TestServiceChangesMasterPasswordWithoutReencryptingCredentials(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	now := time.Date(2026, time.July, 24, 10, 0, 0, 0, time.UTC)
	manager := session.NewManagerWithOptions(credentialStore, session.Options{Now: func() time.Time { return now }})
	service := NewService(credentialStore, manager)
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "old-master-password"})
	callService[struct{}](t, service, "keys.change_master_password", ChangeMasterPasswordParams{
		OldMasterPassword: "old-master-password", NewMasterPassword: "new-master-password",
	})
	callService[struct{}](t, service, "lock", nil)

	oldParams, _ := json.Marshal(UnlockParams{MasterPassword: "old-master-password"})
	if _, err := service.Handle(context.Background(), "unlock", oldParams); !errors.Is(err, store.ErrUnlockFailed) {
		t.Fatalf("unlock with old master password error = %v, want ErrUnlockFailed", err)
	}
	now = now.Add(time.Second)
	result := callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "new-master-password"})
	if result.Created || !result.Unlocked {
		t.Fatalf("unlock with new master password = %#v", result)
	}
}

func TestServiceReturnsFingerprintConfirmationBeforeSSHConnectionTest(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	service := NewService(credentialStore, session.NewManager(credentialStore), WithSSHTransport(&controlFakeSSHTransport{fingerprint: "SHA256:control-test"}))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	result := callService[SSHTestResult](t, service, "ssh.test_target", SSHTestParams{
		Target:   store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true},
		Password: "ssh-password",
	})
	if !result.RequiresFingerprintConfirmation || result.Fingerprint != "SHA256:control-test" {
		t.Fatalf("SSH test result = %#v", result)
	}
}

func TestServiceTestsDatabaseTargetBeforeSavingCredentials(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	instance := store.DatabaseInstance{
		Host: "192.0.2.30", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "database:192.0.2.30:5432:read", Enabled: true,
	}
	result := callService[DatabaseTestResult](t, service, "database.test_target", DatabaseTestParams{
		Instance: instance, ReadPassword: "database-password",
	})
	if result.TransportSecurity != store.TransportTLSUnverified || len(transport.tested) != 1 {
		t.Fatalf("database test result = %#v, calls = %#v", result, transport.tested)
	}

	instance.TransportSecurity = store.TransportTLSVerified
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "database-password",
	})
	targets := callService[TargetsResult](t, service, "targets.list", nil)
	if len(transport.tested) != 2 || len(targets.Databases) != 1 || targets.Databases[0].TransportSecurity != store.TransportTLSUnverified {
		t.Fatalf("database targets = %#v", targets.Databases)
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}
	if strings.Contains(string(encoded), "database-password") {
		t.Fatalf("target response exposed password: %s", encoded)
	}
}

func TestServiceStoresDatabaseVersionVerifiedByCandidateValidation(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{
		security: dbtransport.SecurityTLSUnverified,
		version:  dbtransport.DatabaseVersion{Major: 16},
	}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	instance := store.DatabaseInstance{
		Host: "192.0.2.34", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "read-password",
	})

	saved := callService[TargetsResult](t, service, "targets.list", nil).Databases
	if len(saved) != 1 || saved[0].MajorVersion != 16 || saved[0].VersionStatus != store.DatabaseVersionVerified {
		t.Fatalf("候选验证后的数据库版本状态 = %#v", saved)
	}
}

func TestServiceRegistersDatabaseWithUnverifiedVersionWhenProbeFails(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{
		security:   dbtransport.SecurityTLSUnverified,
		versionErr: errors.New("数据库版本探测不可用"),
	}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})

	instance := store.DatabaseInstance{
		Host: "192.0.2.35", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "read-password",
	})

	saved := callService[TargetsResult](t, service, "targets.list", nil).Databases
	if len(saved) != 1 || saved[0].MajorVersion != 0 || saved[0].VersionStatus != store.DatabaseVersionUnverified {
		t.Fatalf("版本探测失败后的数据库状态 = %#v", saved)
	}
}

func TestServiceDoesNotTestDatabaseWithForeignCredentialReference(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(transport))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.29", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", WriteUsername: "app_write", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "read-password", WritePassword: "write-password",
	})
	saved := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	remoteTests := len(transport.tested)

	testCases := []struct {
		name     string
		instance store.DatabaseInstance
	}{
		{name: "其他登记目标", instance: func() store.DatabaseInstance {
			updated := saved
			updated.Host = "192.0.2.28"
			return updated
		}()},
		{name: "只读身份", instance: func() store.DatabaseInstance {
			updated := saved
			updated.ReadUsername = "next_read"
			return updated
		}()},
		{name: "可写身份", instance: func() store.DatabaseInstance {
			updated := saved
			updated.WriteUsername = "next_write"
			return updated
		}()},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params, err := json.Marshal(DatabaseTestParams{Instance: testCase.instance})
			if err != nil {
				t.Fatalf("序列化数据库预检参数失败：%v", err)
			}
			if _, err := service.Handle(context.Background(), "database.test_target", params); !errors.Is(err, ipc.ErrInvalidRequest) {
				t.Fatalf("携带外部凭据引用的数据库预检错误 = %v，期望 ipc.ErrInvalidRequest", err)
			}
			if len(transport.tested) != remoteTests {
				t.Fatalf("携带外部凭据引用的数据库预检触发了远端连接：%#v", transport.tested)
			}
		})
	}
}

func TestServiceRevokesDatabaseAuthorityWhenDatabaseTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	revoker := &controlTestRevoker{}
	service := NewService(credentialStore, session.NewManager(credentialStore), WithDatabaseTransport(&controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.31", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "database:192.0.2.31:5432:read", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "initial-password",
	})
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "updated-password",
	})
	callService[struct{}](t, service, "target.set_database_enabled", SetDatabaseInstanceEnabledParams{
		Host: instance.Host, Port: instance.Port, Enabled: false,
	})
	if want := []string{"192.0.2.31:5432", "192.0.2.31:5432"}; !slices.Equal(revoker.databases, want) {
		t.Fatalf("database revocations = %#v, want %#v", revoker.databases, want)
	}
}

func TestServicePreservesDatabaseConfigurationWhenFinalValidationFails(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	transport := &controlFakeDatabaseTransport{security: dbtransport.SecurityTLSUnverified}
	revoker := &controlTestRevoker{}
	manager := session.NewManager(credentialStore)
	service := NewService(credentialStore, manager, WithDatabaseTransport(transport), WithTargetAuthorizationRevoker(revoker))
	callService[UnlockResult](t, service, "unlock", UnlockParams{MasterPassword: "test-master-password"})
	instance := store.DatabaseInstance{
		Host: "192.0.2.32", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", TransportSecurity: store.TransportTLSUnverified, Enabled: true,
	}
	callService[struct{}](t, service, "target.upsert_database", UpsertDatabaseInstanceParams{
		Instance: instance, ReadPassword: "previous-password",
	})
	revoker.databases = nil
	revoker.databaseActivations = nil
	before := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	vault, err := manager.Vault()
	if err != nil {
		t.Fatalf("读取已解锁凭据库失败：%v", err)
	}
	previousPassword, err := vault.Credential(context.Background(), before.ReadCredentialID)
	if err != nil {
		t.Fatalf("读取原只读凭据失败：%v", err)
	}
	defer secret.Zero(previousPassword)

	transport.testErr = errors.New("数据库配置最终连通性校验失败")
	updated := instance
	updated.DefaultDatabase = "app_next"
	params, err := json.Marshal(UpsertDatabaseInstanceParams{Instance: updated, ReadPassword: "replacement-password"})
	if err != nil {
		t.Fatalf("序列化数据库更新参数失败：%v", err)
	}
	if _, err := service.Handle(context.Background(), "target.upsert_database", params); err == nil {
		t.Fatal("最终连通性校验失败的数据库更新意外成功")
	}
	after := callService[TargetsResult](t, service, "targets.list", nil).Databases[0]
	if after != before {
		t.Fatalf("最终校验失败后数据库登记目标发生变化：%#v", after)
	}
	actualPassword, err := vault.Credential(context.Background(), after.ReadCredentialID)
	if err != nil {
		t.Fatalf("读取失败后的只读凭据失败：%v", err)
	}
	defer secret.Zero(actualPassword)
	if !bytes.Equal(actualPassword, previousPassword) {
		t.Fatal("最终校验失败后数据库只读凭据发生变化")
	}
	if want := []string{"192.0.2.32:5432"}; !slices.Equal(revoker.databases, want) {
		t.Fatalf("数据库撤销记录 = %#v，期望 %#v", revoker.databases, want)
	}
	if want := []string{"192.0.2.32:5432"}; !slices.Equal(revoker.databaseActivations, want) {
		t.Fatalf("数据库激活记录 = %#v，期望 %#v", revoker.databaseActivations, want)
	}
}

const controlTestFingerprint = "SHA256:control-test"

func confirmedSSHUpsert(target store.SSHTarget, password string) UpsertSSHTargetParams {
	return UpsertSSHTargetParams{
		Target: target, Password: password, ConfirmedFingerprint: controlTestFingerprint,
	}
}

type controlFakeSSHTransport struct {
	fingerprint string
	probeErr    error
	testErr     error
	probeCalls  int
	testCalls   int
}

type controlTestRevoker struct {
	ssh                 []string
	sshActivations      []string
	sshEvents           []string
	databases           []string
	databaseActivations []string
	onSSH               func(string)
}

func (r *controlTestRevoker) RevokeSSHTarget(target string) {
	r.ssh = append(r.ssh, target)
	r.sshEvents = append(r.sshEvents, "revoke:"+target)
	if r.onSSH != nil {
		r.onSSH(target)
	}
}

func (r *controlTestRevoker) ActivateSSHTarget(target string) {
	r.sshActivations = append(r.sshActivations, target)
	r.sshEvents = append(r.sshEvents, "activate:"+target)
}

func (r *controlTestRevoker) clearSSHAuthorizationEvents() {
	r.ssh = nil
	r.sshActivations = nil
	r.sshEvents = nil
}

func (r *controlTestRevoker) RevokeDatabaseTarget(target string) {
	r.databases = append(r.databases, target)
}

func (r *controlTestRevoker) ActivateDatabaseTarget(target string) {
	r.databaseActivations = append(r.databaseActivations, target)
}

type blockingControlTestRevoker struct {
	mu                     sync.Mutex
	sshEvents              []string
	revocations            int
	activations            int
	blockActivationAt      int
	firstActivationBlocked chan struct{}
	releaseActivation      chan struct{}
	secondRevocation       chan struct{}
	releaseOnce            sync.Once
}

func newBlockingControlTestRevoker() *blockingControlTestRevoker {
	return &blockingControlTestRevoker{
		firstActivationBlocked: make(chan struct{}),
		releaseActivation:      make(chan struct{}),
		secondRevocation:       make(chan struct{}),
	}
}

func (r *blockingControlTestRevoker) armNextActivation() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blockActivationAt = r.activations + 1
}

func (r *blockingControlTestRevoker) RevokeSSHTarget(target string) {
	r.mu.Lock()
	r.revocations++
	revocation := r.revocations
	r.sshEvents = append(r.sshEvents, "revoke:"+target)
	r.mu.Unlock()
	if revocation == 2 {
		close(r.secondRevocation)
	}
}

func (r *blockingControlTestRevoker) ActivateSSHTarget(target string) {
	r.mu.Lock()
	r.activations++
	activation := r.activations
	block := activation == r.blockActivationAt
	r.sshEvents = append(r.sshEvents, "activate:"+target)
	r.mu.Unlock()
	if block {
		close(r.firstActivationBlocked)
		<-r.releaseActivation
	}
}

func (r *blockingControlTestRevoker) RevokeDatabaseTarget(string) {}

func (r *blockingControlTestRevoker) releaseFirstActivation() {
	r.releaseOnce.Do(func() {
		close(r.releaseActivation)
	})
}

func (r *blockingControlTestRevoker) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sshEvents...)
}

type trackingSSHTargetLocker struct {
	mu            sync.Mutex
	stateMu       sync.Mutex
	held          bool
	secondWaiting chan struct{}
	waiterOnce    sync.Once
}

func newTrackingSSHTargetLocker() *trackingSSHTargetLocker {
	return &trackingSSHTargetLocker{secondWaiting: make(chan struct{})}
}

func (l *trackingSSHTargetLocker) Lock() {
	l.stateMu.Lock()
	waiting := l.held
	l.stateMu.Unlock()
	if waiting {
		l.waiterOnce.Do(func() {
			close(l.secondWaiting)
		})
	}
	l.mu.Lock()
	l.stateMu.Lock()
	l.held = true
	l.stateMu.Unlock()
}

func (l *trackingSSHTargetLocker) Unlock() {
	l.stateMu.Lock()
	l.held = false
	l.stateMu.Unlock()
	l.mu.Unlock()
}

func (f *controlFakeSSHTransport) ProbeHostKey(context.Context, sshtransport.Endpoint) (string, error) {
	f.probeCalls++
	if f.probeErr != nil {
		return "", f.probeErr
	}
	return f.fingerprint, nil
}

func (f *controlFakeSSHTransport) TestCommand(context.Context, sshtransport.Endpoint) error {
	f.testCalls++
	return f.testErr
}

var _ sshservice.Transport = (*controlFakeSSHTransport)(nil)

type blockingControlSSHTransport struct {
	fingerprint string
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
}

func (f *blockingControlSSHTransport) ProbeHostKey(context.Context, sshtransport.Endpoint) (string, error) {
	return f.fingerprint, nil
}

func (f *blockingControlSSHTransport) TestCommand(ctx context.Context, _ sshtransport.Endpoint) error {
	f.startOnce.Do(func() { close(f.started) })
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ sshservice.Transport = (*blockingControlSSHTransport)(nil)

type controlFakeDatabaseTransport struct {
	security   dbtransport.Security
	version    dbtransport.DatabaseVersion
	versionErr error
	tested     []dbtransport.Endpoint
	testErr    error
}

func (f *controlFakeDatabaseTransport) Test(_ context.Context, endpoint dbtransport.Endpoint) (dbtransport.Security, error) {
	f.tested = append(f.tested, endpoint)
	if f.testErr != nil {
		return "", f.testErr
	}
	return f.security, nil
}

func (f *controlFakeDatabaseTransport) ProbeVersion(context.Context, dbtransport.Endpoint) (dbtransport.DatabaseVersion, error) {
	return f.version, f.versionErr
}

func (f *controlFakeDatabaseTransport) ListDatabases(context.Context, dbtransport.Endpoint) (dbtransport.DatabaseListResult, error) {
	return dbtransport.DatabaseListResult{TransportSecurity: f.security}, nil
}

func (f *controlFakeDatabaseTransport) Query(context.Context, dbtransport.Endpoint, string, dbtransport.Limits) (dbtransport.QueryResult, error) {
	return dbtransport.QueryResult{TransportSecurity: f.security}, nil
}

func (f *controlFakeDatabaseTransport) ExecuteStatements(context.Context, dbtransport.Endpoint, []string) (dbtransport.ExecutionResult, error) {
	return dbtransport.ExecutionResult{TransportSecurity: f.security}, nil
}

type controlTestAuditor struct {
	mu      sync.Mutex
	entries []auditlog.Event
	calls   int
	failAt  int
	err     error
}

func (a *controlTestAuditor) Record(_ context.Context, event auditlog.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.failAt == a.calls {
		if a.err != nil {
			return a.err
		}
		return errors.New("configured audit failure")
	}
	a.entries = append(a.entries, event)
	return nil
}

func (a *controlTestAuditor) Events() []auditlog.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditlog.Event(nil), a.entries...)
}

type controlTestDispatchBarrier struct {
	mu       sync.Mutex
	locked   bool
	inFlight int
	drained  chan struct{}
}

type controlTestDispatchLease struct {
	barrier  *controlTestDispatchBarrier
	started  bool
	finished bool
}

func newControlTestDispatchBarrier() *controlTestDispatchBarrier {
	return &controlTestDispatchBarrier{}
}

func (b *controlTestDispatchBarrier) Acquire() DispatchLease {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.locked {
		return nil
	}
	return &controlTestDispatchLease{barrier: b}
}

func (l *controlTestDispatchLease) BeginDispatch() bool {
	l.barrier.mu.Lock()
	defer l.barrier.mu.Unlock()
	if l.started || l.barrier.locked {
		return false
	}
	l.started = true
	if l.barrier.inFlight == 0 {
		l.barrier.drained = make(chan struct{})
	}
	l.barrier.inFlight++
	return true
}

func (l *controlTestDispatchLease) FinishDispatch() {
	l.barrier.mu.Lock()
	if l.finished || !l.started {
		l.barrier.mu.Unlock()
		return
	}
	l.finished = true
	l.barrier.inFlight--
	var drained chan struct{}
	if l.barrier.inFlight == 0 {
		drained = l.barrier.drained
		l.barrier.drained = nil
	}
	l.barrier.mu.Unlock()
	if drained != nil {
		close(drained)
	}
}

func (b *controlTestDispatchBarrier) Lock(ctx context.Context) error {
	b.mu.Lock()
	b.locked = true
	drained := b.drained
	b.mu.Unlock()
	if drained == nil {
		return nil
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *controlTestDispatchBarrier) Unlock() {
	b.mu.Lock()
	b.locked = false
	b.mu.Unlock()
}

func callService[T any](t *testing.T, service *Service, method string, params any) T {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, err := service.Handle(context.Background(), method, encoded)
	if err != nil {
		t.Fatalf("Handle(%q) error = %v", method, err)
	}
	value, ok := result.(T)
	if !ok {
		t.Fatalf("Handle(%q) result type = %T", method, result)
	}
	return value
}

func assertSSHAuthorizationEvents(t *testing.T, revoker *controlTestRevoker, want ...string) {
	t.Helper()
	if !slices.Equal(revoker.sshEvents, want) {
		t.Fatalf("SSH authorization events = %#v, want %#v", revoker.sshEvents, want)
	}
}

func assertCandidateAuditEvent(t *testing.T, event auditlog.Event, phase, targetKind, targetID, status string) {
	t.Helper()
	if event.Phase != phase || event.Action != "candidate_target_validation" || event.Target.Kind != targetKind || event.Target.ID != targetID || event.Result.Status != status {
		t.Fatalf("candidate audit event = %#v", event)
	}
	if event.SSHCommand != "" || event.SQL != "" {
		t.Fatalf("candidate audit event unexpectedly carries operation content: %#v", event)
	}
}
