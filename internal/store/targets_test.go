package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSSHTargetManagementRoundTrip(t *testing.T) {
	t.Parallel()

	store := openTargetTestStore(t)
	seedTargetCredential(t, store, "ssh-192.0.2.15")
	target := SSHTarget{
		IP:            "192.0.2.15",
		Mode:          SSHDirect,
		SSHPort:       2222,
		LoginUsername: "ops",
		CredentialID:  "ssh-192.0.2.15",
		Description:   "web node",
		Environment:   "production",
		Enabled:       true,
	}
	if err := store.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}

	target.Description = "web node updated"
	target.Enabled = false
	if err := store.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("update UpsertSSHTarget() error = %v", err)
	}

	targets, err := store.ListSSHTargets(context.Background())
	if err != nil {
		t.Fatalf("ListSSHTargets() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("target count = %d, want 1", len(targets))
	}
	if got := targets[0]; got.IP != target.IP || got.SSHPort != 2222 || got.Description != "web node updated" || got.Enabled || got.Revision != 2 {
		t.Fatalf("stored target = %#v", got)
	}
	if targets[0].RemotePlatform != SSHRemotePlatformLinux {
		t.Fatalf("stored remote platform = %q, want %q", targets[0].RemotePlatform, SSHRemotePlatformLinux)
	}

	if err := store.SetSSHTargetEnabled(context.Background(), target.IP, true); !errors.Is(err, ErrCandidateVerificationRequired) {
		t.Fatalf("SetSSHTargetEnabled() error = %v，期望 ErrCandidateVerificationRequired", err)
	}
	targets, err = store.ListSSHTargets(context.Background())
	if err != nil || targets[0].Enabled {
		t.Fatalf("未经候选验证重新启用的目标状态 = %#v, error = %v", targets, err)
	}
}

func TestSSHTargetRejectsUnsupportedRemotePlatform(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-windows-target")
	target := SSHTarget{
		IP: "192.0.2.201", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-windows-target",
		RemotePlatform: "windows",
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); !errors.Is(err, ErrUnsupportedRemotePlatform) {
		t.Fatalf("UpsertSSHTarget() error = %v, want ErrUnsupportedRemotePlatform", err)
	}
	if err := ValidateSSHTargetConfiguration(target); !errors.Is(err, ErrUnsupportedRemotePlatform) {
		t.Fatalf("ValidateSSHTargetConfiguration() error = %v, want ErrUnsupportedRemotePlatform", err)
	}
}

func TestSSHTargetPersistsCommandBlacklistPatterns(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-command-blacklist")
	target := SSHTarget{
		IP:                       "192.0.2.53",
		Mode:                     SSHDirect,
		LoginUsername:            "ops",
		CredentialID:             "ssh-command-blacklist",
		CommandBlacklistPatterns: []string{"rm /data/.*", "passwd.*", "rm /data/.*"},
		Enabled:                  true,
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}

	saved, err := credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if want := []string{"rm /data/.*", "passwd.*"}; !reflect.DeepEqual(saved.CommandBlacklistPatterns, want) {
		t.Fatalf("CommandBlacklistPatterns = %#v, want %#v", saved.CommandBlacklistPatterns, want)
	}
	revision := saved.Revision

	saved.CommandBlacklistPatterns = append(saved.CommandBlacklistPatterns, "cat /etc/passwd")
	if err := credentialStore.UpsertSSHTarget(context.Background(), saved); err != nil {
		t.Fatalf("update UpsertSSHTarget() error = %v", err)
	}
	updated, err := credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("load updated SSH target: %v", err)
	}
	if updated.Revision != revision+1 {
		t.Fatalf("command blacklist update revision = %d, want %d", updated.Revision, revision+1)
	}
}

func TestSSHTargetRejectsInvalidCommandBlacklistPatterns(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-invalid-command-blacklist")
	base := SSHTarget{
		IP: "192.0.2.54", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-invalid-command-blacklist", Enabled: true,
	}
	invalid := []SSHTarget{
		func() SSHTarget { target := base; target.CommandBlacklistPatterns = []string{"["}; return target }(),
		func() SSHTarget { target := base; target.CommandBlacklistPatterns = []string{""}; return target }(),
	}
	for _, target := range invalid {
		if err := credentialStore.UpsertSSHTarget(context.Background(), target); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("UpsertSSHTarget(%#v) error = %v, want ErrInvalidTarget", target, err)
		}
	}
}

func TestSSHTargetManagementRejectsNonDirectMode(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-192.0.2.99")
	if err := credentialStore.UpsertSSHTarget(context.Background(), SSHTarget{
		IP: "192.0.2.99", Mode: SSHMode("relay"), SSHPort: 22,
		LoginUsername: "ops", CredentialID: "ssh-192.0.2.99", Enabled: true,
	}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("non-direct SSH target error = %v, want ErrInvalidTarget", err)
	}
}

func TestDatabaseTargetManagementRoundTrip(t *testing.T) {
	t.Parallel()

	store := openTargetTestStore(t)
	seedTargetCredential(t, store, "database-read")
	seedTargetCredential(t, store, "database-write")
	instance := DatabaseInstance{
		Host:              "2001:db8::10",
		Port:              5432,
		Engine:            EnginePostgreSQL,
		DefaultDatabase:   "app",
		ReadUsername:      "app_read",
		WriteUsername:     "app_write",
		ReadCredentialID:  "database-read",
		WriteCredentialID: "database-write",
		Description:       "application database",
		Environment:       "staging",
		TransportSecurity: TransportTLSUnverified,
		Enabled:           true,
	}
	if err := store.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}

	instance.DefaultDatabase = "app_next"
	instance.Enabled = false
	if err := store.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("update UpsertDatabaseInstance() error = %v", err)
	}

	instances, err := store.ListDatabaseInstances(context.Background())
	if err != nil {
		t.Fatalf("ListDatabaseInstances() error = %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("instance count = %d, want 1", len(instances))
	}
	if got := instances[0]; got.Host != "2001:db8::10" || got.DefaultDatabase != "app_next" || got.ReadUsername != "app_read" || got.WriteUsername != "app_write" || got.TransportSecurity != TransportTLSUnverified || got.TransportPolicy != DatabaseLegacyPlaintext || got.Revision != 2 || got.Enabled {
		t.Fatalf("stored instance = %#v", got)
	}

	if err := store.SetDatabaseInstanceEnabled(context.Background(), instance.Host, instance.Port, true); !errors.Is(err, ErrCandidateVerificationRequired) {
		t.Fatalf("SetDatabaseInstanceEnabled() error = %v，期望 ErrCandidateVerificationRequired", err)
	}
	instances, err = store.ListDatabaseInstances(context.Background())
	if err != nil || instances[0].Enabled {
		t.Fatalf("未经候选验证重新启用的数据库状态 = %#v, error = %v", instances, err)
	}
}

func TestExecutionRevisionIgnoresDescriptiveTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-execution-revision")
	sshTarget := SSHTarget{
		IP: "192.0.2.16", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-execution-revision",
		Description: "before", Environment: "staging", Enabled: true,
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), sshTarget); err != nil {
		t.Fatalf("写入 SSH 登记目标失败：%v", err)
	}
	sshSaved, err := credentialStore.SSHTarget(context.Background(), sshTarget.IP)
	if err != nil {
		t.Fatalf("读取 SSH 登记目标失败：%v", err)
	}
	sshRevision := sshSaved.Revision
	sshSaved.Description = "after"
	sshSaved.Environment = "production"
	if err := credentialStore.UpsertSSHTarget(context.Background(), sshSaved); err != nil {
		t.Fatalf("更新 SSH 描述性字段失败：%v", err)
	}
	sshUpdated, err := credentialStore.SSHTarget(context.Background(), sshTarget.IP)
	if err != nil {
		t.Fatalf("读取更新后的 SSH 登记目标失败：%v", err)
	}
	if sshUpdated.Revision != sshRevision {
		t.Fatalf("SSH 描述性更新改变执行版本：更新前 %d，更新后 %d", sshRevision, sshUpdated.Revision)
	}

	seedTargetCredential(t, credentialStore, "database-execution-read")
	database := DatabaseInstance{
		Host: "192.0.2.17", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "reader", ReadCredentialID: "database-execution-read",
		Description: "before", Environment: "staging", TransportSecurity: TransportPlaintext, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), database); err != nil {
		t.Fatalf("写入数据库登记目标失败：%v", err)
	}
	databaseSaved, err := credentialStore.DatabaseInstance(context.Background(), database.Host, database.Port)
	if err != nil {
		t.Fatalf("读取数据库登记目标失败：%v", err)
	}
	databaseRevision := databaseSaved.Revision
	databaseSaved.Description = "after"
	databaseSaved.Environment = "production"
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), databaseSaved); err != nil {
		t.Fatalf("更新数据库描述性字段失败：%v", err)
	}
	databaseUpdated, err := credentialStore.DatabaseInstance(context.Background(), database.Host, database.Port)
	if err != nil {
		t.Fatalf("读取更新后的数据库登记目标失败：%v", err)
	}
	if databaseUpdated.Revision != databaseRevision {
		t.Fatalf("数据库描述性更新改变执行版本：更新前 %d，更新后 %d", databaseRevision, databaseUpdated.Revision)
	}

	databaseUpdated.MajorVersion = 16
	databaseUpdated.VersionStatus = DatabaseVersionVerified
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), databaseUpdated); err != nil {
		t.Fatalf("更新数据库版本展示信息失败：%v", err)
	}
	databaseWithVersion, err := credentialStore.DatabaseInstance(context.Background(), database.Host, database.Port)
	if err != nil {
		t.Fatalf("读取带版本展示信息的数据库登记目标失败：%v", err)
	}
	if databaseWithVersion.Revision != databaseRevision {
		t.Fatalf("数据库版本展示信息改变执行版本：更新前 %d，更新后 %d", databaseRevision, databaseWithVersion.Revision)
	}
}

func TestDatabaseTransportPolicyValidation(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "database-read")
	base := DatabaseInstance{
		Host: "192.0.2.24", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "reader", ReadCredentialID: "database-read", TransportSecurity: TransportTLSVerified, Enabled: true,
	}
	invalid := base
	invalid.TransportPolicy = DatabaseTLSVerified
	invalid.TLSCAPath = "relative-ca.pem"
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), invalid); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("relative CA error = %v, want ErrInvalidTarget", err)
	}
	valid := base
	valid.TransportPolicy = DatabaseTLSVerified
	valid.TLSCAPath = filepath.Join(t.TempDir(), "database-ca.pem")
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), valid); err != nil {
		t.Fatalf("verified TLS target error = %v", err)
	}
	invalid = valid
	invalid.TransportPolicy = DatabaseLegacyPlaintext
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), invalid); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("legacy target with CA error = %v, want ErrInvalidTarget", err)
	}
}

func TestDatabaseInstanceLooksUpOnlyRegisteredHostAndPort(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "database-read")
	instance := DatabaseInstance{
		Host: "192.0.2.20", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "reader", ReadCredentialID: "database-read", TransportSecurity: TransportTLSUnverified, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}
	got, err := credentialStore.DatabaseInstance(context.Background(), "192.0.2.20", 5432)
	if err != nil {
		t.Fatalf("DatabaseInstance() error = %v", err)
	}
	if got.Host != instance.Host || got.Port != instance.Port || got.Engine != instance.Engine || !got.Enabled {
		t.Fatalf("DatabaseInstance() = %#v", got)
	}
	if _, err := credentialStore.DatabaseInstance(context.Background(), "192.0.2.20", 3306); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("DatabaseInstance(unregistered) error = %v, want ErrTargetNotFound", err)
	}
}

func TestDatabaseTargetRequiresReadAccountAndCompleteOptionalWriteAccount(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "database-read")
	seedTargetCredential(t, credentialStore, "database-read-same")
	seedTargetCredential(t, credentialStore, "database-write")
	base := DatabaseInstance{
		Host: "192.0.2.44", Port: 3306, Engine: EngineMySQL, ReadUsername: "reader",
		ReadCredentialID: "database-read", TransportSecurity: TransportPlaintext, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), base); err != nil {
		t.Fatalf("single-account UpsertDatabaseInstance() error = %v", err)
	}

	base.Host = "192.0.2.45"
	base.WriteUsername = "reader"
	base.ReadCredentialID = "database-read-same"
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), base); err != nil {
		t.Fatalf("same read/write account without a second credential error = %v", err)
	}

	base.Host = "192.0.2.46"
	base.WriteUsername = "writer"
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), base); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("write username without credential error = %v, want ErrInvalidTarget", err)
	}

	base.Host = "192.0.2.47"
	base.WriteUsername = ""
	base.WriteCredentialID = "database-write"
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), base); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("write credential without username error = %v, want ErrInvalidTarget", err)
	}
}

func TestDatabaseTargetAllowsSameReadAndWriteLoginIdentityWithSeparateCredentials(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "database-read-identity")
	seedTargetCredential(t, credentialStore, "database-write-identity")
	instance := DatabaseInstance{
		Host: "192.0.2.47", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app", ReadCredentialID: "database-read-identity",
		WriteUsername: "app", WriteCredentialID: "database-write-identity",
		TransportSecurity: TransportPlaintext, Enabled: true,
	}

	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("同一读写数据库登录身份错误 = %v", err)
	}
	stored, err := credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port)
	if err != nil || stored.ReadUsername != "app" || stored.WriteUsername != "app" || stored.ReadCredentialID == stored.WriteCredentialID {
		t.Fatalf("同名读写账号保存结果 = %#v，错误 = %v", stored, err)
	}
}

func TestSetTargetEnabledRejectsUnknownAndInvalidTargets(t *testing.T) {
	t.Parallel()

	store := openTargetTestStore(t)
	if err := store.SetSSHTargetEnabled(context.Background(), "192.0.2.99", true); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("unknown SSH target error = %v, want ErrTargetNotFound", err)
	}
	if err := store.UpsertDatabaseInstance(context.Background(), DatabaseInstance{Host: "host-name", Port: 3306, Engine: EngineMySQL}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("invalid database target error = %v, want ErrInvalidTarget", err)
	}
}

func TestTargetVerificationStateBlocksDirectReenable(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	seedTargetCredential(t, credentialStore, "ssh-verification-state")
	sshTarget := SSHTarget{
		IP: "192.0.2.60", Mode: SSHDirect, LoginUsername: "ops", CredentialID: "ssh-verification-state",
		Enabled: true, IdentityStatus: SSHIdentityVerified,
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), sshTarget); err != nil {
		t.Fatalf("写入 SSH 登记目标失败：%v", err)
	}
	if err := credentialStore.MarkSSHTargetIdentityUnconfirmed(context.Background(), sshTarget.IP); err != nil {
		t.Fatalf("隔离 SSH 主机身份失败：%v", err)
	}
	sshSaved, err := credentialStore.SSHTarget(context.Background(), sshTarget.IP)
	if err != nil {
		t.Fatalf("读取 SSH 隔离状态失败：%v", err)
	}
	if sshSaved.Enabled || sshSaved.IdentityStatus != SSHIdentityUnconfirmed {
		t.Fatalf("SSH 身份隔离状态 = %#v", sshSaved)
	}
	if err := credentialStore.SetSSHTargetEnabled(context.Background(), sshTarget.IP, true); !errors.Is(err, ErrCandidateVerificationRequired) {
		t.Fatalf("未做候选验证重新启用 SSH 错误 = %v，期望 ErrCandidateVerificationRequired", err)
	}

	seedTargetCredential(t, credentialStore, "database-verification-read")
	database := DatabaseInstance{
		Host: "192.0.2.61", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "reader", ReadCredentialID: "database-verification-read",
		TransportSecurity: TransportPlaintext, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), database); err != nil {
		t.Fatalf("写入数据库登记目标失败：%v", err)
	}
	if err := credentialStore.SetDatabaseInstanceEnabled(context.Background(), database.Host, database.Port, false); err != nil {
		t.Fatalf("禁用数据库登记目标失败：%v", err)
	}
	if err := credentialStore.SetDatabaseInstanceEnabled(context.Background(), database.Host, database.Port, true); !errors.Is(err, ErrCandidateVerificationRequired) {
		t.Fatalf("未做候选验证重新启用数据库错误 = %v，期望 ErrCandidateVerificationRequired", err)
	}
}

func TestDeleteSSHTargetRemovesHostKeyAndUnreferencedCredential(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	credentialID := "ssh-delete"
	seedTargetCredential(t, credentialStore, credentialID)
	target := SSHTarget{
		IP: "192.0.2.51", Mode: SSHDirect, SSHPort: 2222, LoginUsername: "ops", CredentialID: credentialID, Enabled: true,
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	if err := credentialStore.PinInitialHostKey(context.Background(), target.IP, target.SSHPort, "SHA256:delete-test"); err != nil {
		t.Fatalf("PinInitialHostKey() error = %v", err)
	}

	if err := credentialStore.DeleteSSHTarget(context.Background(), target.IP); err != nil {
		t.Fatalf("DeleteSSHTarget() error = %v", err)
	}
	if _, err := credentialStore.SSHTarget(context.Background(), target.IP); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("SSHTarget() error = %v, want ErrTargetNotFound", err)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), target.IP, target.SSHPort); !errors.Is(err, ErrHostKeyNotFound) {
		t.Fatalf("HostKeyFingerprint() error = %v, want ErrHostKeyNotFound", err)
	}
	if credentialExists(t, credentialStore, credentialID) {
		t.Fatal("unreferenced SSH credential remains after target deletion")
	}
	if err := credentialStore.DeleteSSHTarget(context.Background(), target.IP); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("second DeleteSSHTarget() error = %v, want ErrTargetNotFound", err)
	}
}

func TestDeleteDatabaseInstanceRemovesOnlyItsTargetSpecificCredentials(t *testing.T) {
	t.Parallel()

	credentialStore := openTargetTestStore(t)
	sshCredentialID := "ssh-credential"
	readCredentialID := "database-read-delete"
	writeCredentialID := "database-write-delete"
	seedTargetCredential(t, credentialStore, sshCredentialID)
	seedTargetCredential(t, credentialStore, readCredentialID)
	seedTargetCredential(t, credentialStore, writeCredentialID)
	if err := credentialStore.UpsertSSHTarget(context.Background(), SSHTarget{
		IP: "192.0.2.52", Mode: SSHDirect, LoginUsername: "ops", CredentialID: sshCredentialID, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	instance := DatabaseInstance{
		Host: "192.0.2.53", Port: 5432, Engine: EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "reader", ReadCredentialID: readCredentialID,
		WriteUsername: "writer", WriteCredentialID: writeCredentialID,
		TransportSecurity: TransportTLSUnverified, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}

	if err := credentialStore.DeleteDatabaseInstance(context.Background(), instance.Host, instance.Port); err != nil {
		t.Fatalf("DeleteDatabaseInstance() error = %v", err)
	}
	if _, err := credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("DatabaseInstance() error = %v, want ErrTargetNotFound", err)
	}
	if !credentialExists(t, credentialStore, sshCredentialID) {
		t.Fatal("SSH 目标凭据随数据库登记目标被删除")
	}
	if credentialExists(t, credentialStore, readCredentialID) {
		t.Fatal("无引用的数据库只读凭据仍然存在")
	}
	if credentialExists(t, credentialStore, writeCredentialID) {
		t.Fatal("无引用的数据库可写凭据仍然存在")
	}
}

func openTargetTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedTargetCredential(t *testing.T, store *Store, id string) {
	t.Helper()
	vault, err := store.Initialize(context.Background(), []byte("test-master-password"))
	if errors.Is(err, ErrAlreadyInitialized) {
		vault, err = store.Unlock(context.Background(), []byte("test-master-password"))
	}
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	t.Cleanup(vault.Lock)
	if err := vault.PutCredential(context.Background(), id, "test", []byte("test-secret")); err != nil {
		t.Fatalf("PutCredential(%q) error = %v", id, err)
	}
}

func credentialExists(t *testing.T, store *Store, id string) bool {
	t.Helper()
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM credentials WHERE id = ?", id).Scan(&count); err != nil {
		t.Fatalf("count credential %q: %v", id, err)
	}
	return count == 1
}
