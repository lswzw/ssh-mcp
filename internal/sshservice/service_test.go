package sshservice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

func TestServiceRequiresFingerprintConfirmationBeforeDirectConnectionTest(t *testing.T) {
	t.Parallel()
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()

	transport := &fakeTransport{fingerprint: "SHA256:test-host"}
	service := New(credentialStore, transport)
	target := store.SSHTarget{IP: "192.0.2.10", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	result, err := service.TestTarget(context.Background(), vault, target, []byte("password"), "")
	if err != nil {
		t.Fatalf("TestTarget() error = %v", err)
	}
	if !result.RequiresFingerprintConfirmation || result.Fingerprint != "SHA256:test-host" || transport.commandTested {
		t.Fatalf("first test result = %#v, command tested = %v", result, transport.commandTested)
	}

	result, err = service.TestTarget(context.Background(), vault, target, []byte("password"), result.Fingerprint)
	if err != nil {
		t.Fatalf("confirmed TestTarget() error = %v", err)
	}
	if result.RequiresFingerprintConfirmation || !transport.commandTested {
		t.Fatalf("confirmed test result = %#v, command tested = %v", result, transport.commandTested)
	}
	if _, err := credentialStore.HostKeyFingerprint(context.Background(), target.IP, target.SSHPort); !errors.Is(err, store.ErrHostKeyNotFound) {
		t.Fatalf("候选测试意外持久化主机身份：%v", err)
	}
}

func TestServiceRequestsConfirmationAgainWhenSSHTargetFingerprintChanges(t *testing.T) {
	t.Parallel()
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("初始化凭据库失败：%v", err)
	}
	defer vault.Lock()

	transport := &fakeTransport{fingerprint: "SHA256:first"}
	service := New(credentialStore, transport)
	target := store.SSHTarget{IP: "192.0.2.12", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	first, err := service.TestTarget(context.Background(), vault, target, []byte("password"), "")
	if err != nil || !first.RequiresFingerprintConfirmation || first.Fingerprint != "SHA256:first" {
		t.Fatalf("首次 SSH 配置变更主机身份确认结果 = %#v，错误 = %v", first, err)
	}

	transport.fingerprint = "SHA256:second"
	transport.commandTested = false
	second, err := service.TestTarget(context.Background(), vault, target, []byte("password"), first.Fingerprint)
	if err != nil || !second.RequiresFingerprintConfirmation || second.Fingerprint != "SHA256:second" || transport.commandTested {
		t.Fatalf("主机身份变化后的确认结果 = %#v，连通性测试 = %v，错误 = %v", second, transport.commandTested, err)
	}

	confirmed, err := service.TestTarget(context.Background(), vault, target, []byte("password"), second.Fingerprint)
	if err != nil || confirmed.RequiresFingerprintConfirmation || confirmed.Fingerprint != "SHA256:second" || !transport.commandTested {
		t.Fatalf("重新确认后的 SSH 配置变更结果 = %#v，连通性测试 = %v，错误 = %v", confirmed, transport.commandTested, err)
	}
}

func TestServiceRequiresExactConfirmedFingerprintForConfigurationValidation(t *testing.T) {
	t.Parallel()
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()

	transport := &fakeTransport{fingerprint: "SHA256:candidate"}
	service := New(credentialStore, transport)
	target := store.SSHTarget{IP: "192.0.2.11", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", Enabled: true}
	result, err := service.ValidateTargetConfiguration(context.Background(), vault, target, []byte("password"), "SHA256:other")
	if err != nil {
		t.Fatalf("验证 SSH 配置变更失败：%v", err)
	}
	if !result.RequiresFingerprintConfirmation || result.Fingerprint != transport.fingerprint || transport.commandTested {
		t.Fatalf("不匹配的候选确认结果 = %#v，连通性测试 = %v", result, transport.commandTested)
	}
	result, err = service.ValidateTargetConfiguration(context.Background(), vault, target, []byte("password"), transport.fingerprint)
	if err != nil {
		t.Fatalf("验证已确认 SSH 配置变更失败：%v", err)
	}
	if result.RequiresFingerprintConfirmation || result.Fingerprint != transport.fingerprint || !transport.commandTested {
		t.Fatalf("已确认候选验证结果 = %#v，连通性测试 = %v", result, transport.commandTested)
	}
}

func TestServiceExecutesOnlyWithPinnedTargetAndDecryptedCredential(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()
	if err := vault.PutCredential(context.Background(), "ssh-password", "ssh", []byte("password")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	if err := credentialStore.PinInitialHostKey(context.Background(), "192.0.2.30", 22, "SHA256:pinned"); err != nil {
		t.Fatalf("PinInitialHostKey() error = %v", err)
	}
	executor := &fakeExecutor{}
	service := New(credentialStore, &fakeTransport{}, executor)
	target := store.SSHTarget{IP: "192.0.2.30", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-password", Enabled: true, IdentityStatus: store.SSHIdentityVerified}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	target, err = credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if _, err := service.Execute(context.Background(), vault, target, "free -m", false, 1024); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if executor.endpoint.Fingerprint != "SHA256:pinned" || executor.command != "free -m" || string(executor.endpoint.Password) != "password" {
		t.Fatalf("executor call = %#v", executor)
	}
}

func TestServiceRejectsSSHExecutionAfterTargetChanges(t *testing.T) {
	t.Parallel()

	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer credentialStore.Close()
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer vault.Lock()
	if err := vault.PutCredential(context.Background(), "ssh-password", "ssh", []byte("password")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	target := store.SSHTarget{IP: "192.0.2.31", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-password", Enabled: true, IdentityStatus: store.SSHIdentityVerified}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	target, err = credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if err := credentialStore.SetSSHTargetEnabled(context.Background(), target.IP, false); err != nil {
		t.Fatalf("SetSSHTargetEnabled() error = %v", err)
	}
	if _, err := New(credentialStore, &fakeTransport{}, &fakeExecutor{}).Execute(context.Background(), vault, target, "free -m", false, 1024); !errors.Is(err, store.ErrTargetChanged) {
		t.Fatalf("Execute() error = %v, want ErrTargetChanged", err)
	}
}

type fakeTransport struct {
	fingerprint   string
	commandTested bool
}

func (f *fakeTransport) ProbeHostKey(context.Context, sshtransport.Endpoint) (string, error) {
	return f.fingerprint, nil
}

func (f *fakeTransport) TestCommand(context.Context, sshtransport.Endpoint) error {
	f.commandTested = true
	return nil
}

type fakeExecutor struct {
	endpoint sshtransport.Endpoint
	command  string
}

func (f *fakeExecutor) Execute(_ context.Context, endpoint sshtransport.Endpoint, command string, _ bool, _ int) (sshtransport.ExecutionResult, error) {
	endpoint.Password = append([]byte(nil), endpoint.Password...)
	f.endpoint = endpoint
	f.command = command
	return sshtransport.ExecutionResult{}, nil
}
