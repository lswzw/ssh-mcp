package dbservice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/store"
)

func TestServiceTestsReadAndWriteCredentialsBeforeSavingTarget(t *testing.T) {
	t.Parallel()

	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()

	transport := &fakeTransport{security: dbtransport.SecurityTLSUnverified}
	service := New(credentialStore, transport)
	instance := store.DatabaseInstance{
		Host: "192.0.2.20", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "db-read",
		WriteUsername: "app_write", WriteCredentialID: "db-write", Enabled: true,
	}
	result, err := service.TestInstance(context.Background(), vault, instance, CandidateCredentials{
		ReadPassword: []byte("read-password"), WritePassword: []byte("write-password"),
	})
	if err != nil {
		t.Fatalf("TestInstance() error = %v", err)
	}
	if result.TransportSecurity != dbtransport.SecurityTLSUnverified {
		t.Fatalf("security = %q", result.TransportSecurity)
	}
	if len(transport.tested) != 2 || transport.tested[0].Username != "app_read" || transport.tested[1].Username != "app_write" {
		t.Fatalf("tested endpoints = %#v", transport.tested)
	}
}

func TestServiceValidatesReadAndWriteWithUnpersistedCandidateCredentials(t *testing.T) {
	t.Parallel()

	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("初始化凭据库失败：%v", err)
	}
	defer vault.Lock()

	transport := &fakeTransport{security: dbtransport.SecurityTLSVerified}
	service := New(credentialStore, transport)
	instance := store.DatabaseInstance{
		Host: "192.0.2.24", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "调用方读凭据标识",
		WriteUsername: "app_write", Enabled: false,
	}

	result, err := service.ValidateInstanceConfiguration(context.Background(), vault, instance, CandidateCredentials{
		ReadPassword: []byte("candidate-read-password"), WritePassword: []byte("candidate-write-password"),
	})
	if err != nil {
		t.Fatalf("验证数据库配置变更失败：%v", err)
	}
	if result.TransportSecurity != dbtransport.SecurityTLSVerified {
		t.Fatalf("传输安全状态 = %q", result.TransportSecurity)
	}
	if len(transport.tested) != 2 {
		t.Fatalf("测试连接次数 = %d，期望 2", len(transport.tested))
	}
	if transport.tested[0].Username != "app_read" || transport.tested[1].Username != "app_write" {
		t.Fatalf("测试身份 = %#v", transport.tested)
	}
}

func TestServiceUsesReadCredentialsForQueriesAndWriteCredentialsForTransactions(t *testing.T) {
	t.Parallel()

	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()
	for id, password := range map[string]string{"db-read": "read-password", "db-write": "write-password"} {
		if err := vault.PutCredential(context.Background(), id, "test", []byte(password)); err != nil {
			t.Fatalf("PutCredential(%q) error = %v", id, err)
		}
	}

	transport := &fakeTransport{security: dbtransport.SecurityPlaintext}
	service := New(credentialStore, transport)
	instance := store.DatabaseInstance{
		Host: "192.0.2.21", Port: 3306, Engine: store.EngineMySQL, DefaultDatabase: "app",
		ReadUsername: "app_read", ReadCredentialID: "db-read",
		WriteUsername: "app_write", WriteCredentialID: "db-write", TransportSecurity: store.TransportPlaintext, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}
	instance, err = credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port)
	if err != nil {
		t.Fatalf("DatabaseInstance() error = %v", err)
	}
	if _, err := service.ListDatabases(context.Background(), vault, instance); err != nil {
		t.Fatalf("ListDatabases() error = %v", err)
	}
	if _, err := service.Query(context.Background(), vault, instance, "other", "SELECT 1", dbtransport.Limits{MaxRows: 1, MaxBytes: 32}); err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if _, err := service.ExecuteStatements(context.Background(), vault, instance, "other", []string{"UPDATE jobs SET state = 'ready' WHERE id = 1"}); err != nil {
		t.Fatalf("ExecuteStatements() error = %v", err)
	}
	if len(transport.listed) != 1 || transport.listed[0].Username != "app_read" || len(transport.queried) != 1 || transport.queried[0].Username != "app_read" || len(transport.executed) != 1 || transport.executed[0].Username != "app_write" {
		t.Fatalf("credential selection = listed:%#v queried:%#v executed:%#v", transport.listed, transport.queried, transport.executed)
	}
}

func TestServiceRejectsWriteWithoutDedicatedWriteCredential(t *testing.T) {
	t.Parallel()

	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()
	if err := vault.PutCredential(context.Background(), "db-read", "test", []byte("read-password")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}

	transport := &fakeTransport{}
	service := New(credentialStore, transport)
	instance := store.DatabaseInstance{
		Host: "192.0.2.22", Port: 3306, Engine: store.EngineMySQL,
		ReadUsername: "app", ReadCredentialID: "db-read", TransportSecurity: store.TransportPlaintext, Enabled: true,
	}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}
	instance, err = credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port)
	if err != nil {
		t.Fatalf("DatabaseInstance() error = %v", err)
	}
	if _, err := service.ExecuteStatements(context.Background(), vault, instance, "", []string{"UPDATE jobs SET state = 'ready' WHERE id = 1"}); !errors.Is(err, store.ErrWriteCredentialNotConfigured) {
		t.Fatalf("ExecuteStatements() error = %v, want ErrWriteCredentialNotConfigured", err)
	}
	if len(transport.executed) != 0 {
		t.Fatalf("缺少可写身份时仍派发了数据库写入：%#v", transport.executed)
	}
}

func TestServiceRejectsDatabaseExecutionAfterTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore := openTestStore(t)
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()
	if err := vault.PutCredential(context.Background(), "db-read", "test", []byte("read-password")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	instance := store.DatabaseInstance{Host: "192.0.2.23", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app", ReadUsername: "app", ReadCredentialID: "db-read", TransportSecurity: store.TransportPlaintext, Enabled: true}
	if err := credentialStore.UpsertDatabaseInstance(context.Background(), instance); err != nil {
		t.Fatalf("UpsertDatabaseInstance() error = %v", err)
	}
	instance, err = credentialStore.DatabaseInstance(context.Background(), instance.Host, instance.Port)
	if err != nil {
		t.Fatalf("DatabaseInstance() error = %v", err)
	}
	if err := credentialStore.SetDatabaseInstanceEnabled(context.Background(), instance.Host, instance.Port, false); err != nil {
		t.Fatalf("SetDatabaseInstanceEnabled() error = %v", err)
	}
	if _, err := New(credentialStore, &fakeTransport{}).ExecuteStatements(context.Background(), vault, instance, "", []string{"UPDATE jobs SET state = 'ready'"}); !errors.Is(err, store.ErrTargetChanged) {
		t.Fatalf("ExecuteStatements() error = %v, want ErrTargetChanged", err)
	}
}

type fakeTransport struct {
	security   dbtransport.Security
	version    dbtransport.DatabaseVersion
	versionErr error
	tested     []dbtransport.Endpoint
	listed     []dbtransport.Endpoint
	queried    []dbtransport.Endpoint
	executed   []dbtransport.Endpoint
}

func (f *fakeTransport) Test(_ context.Context, endpoint dbtransport.Endpoint) (dbtransport.Security, error) {
	f.tested = append(f.tested, endpoint)
	return f.security, nil
}

func (f *fakeTransport) ProbeVersion(context.Context, dbtransport.Endpoint) (dbtransport.DatabaseVersion, error) {
	return f.version, f.versionErr
}

func (f *fakeTransport) ListDatabases(_ context.Context, endpoint dbtransport.Endpoint) (dbtransport.DatabaseListResult, error) {
	f.listed = append(f.listed, endpoint)
	return dbtransport.DatabaseListResult{Databases: []string{"app"}, TransportSecurity: f.security}, nil
}

func (f *fakeTransport) Query(_ context.Context, endpoint dbtransport.Endpoint, _ string, _ dbtransport.Limits) (dbtransport.QueryResult, error) {
	f.queried = append(f.queried, endpoint)
	return dbtransport.QueryResult{TransportSecurity: f.security}, nil
}

func (f *fakeTransport) ExecuteStatements(_ context.Context, endpoint dbtransport.Endpoint, _ []string) (dbtransport.ExecutionResult, error) {
	f.executed = append(f.executed, endpoint)
	return dbtransport.ExecutionResult{TransportSecurity: f.security}, nil
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = credentialStore.Close() })
	return credentialStore
}
