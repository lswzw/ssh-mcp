package runner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/session"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
	"ssh-mcp/internal/worksession"
)

func TestEngineListsNonSensitiveTargetsWithoutOpeningRemoteSession(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	engine := deps.engine()
	result, err := engine.ListTargets(context.Background())
	if err != nil {
		t.Fatalf("ListTargets() error = %v", err)
	}
	if len(result.SSH) != 1 || result.SSH[0] != (SSHTarget{IP: "192.0.2.10", Port: 22, Enabled: true, FileReadAvailable: true, AllowFileOperations: true}) ||
		len(result.Databases) != 1 || result.Databases[0] != (DatabaseTarget{Target: "192.0.2.20:5432", Engine: store.EnginePostgreSQL, Enabled: true}) {
		t.Fatalf("ListTargets() = %#v", result)
	}
	if deps.openedTUI != 0 || deps.sessions.touched != 0 {
		t.Fatalf("ListTargets() touched execution state: %#v", deps)
	}
}

func TestEngineDescribesRegisteredExecutionSpecificationWithoutSecretsOrRemoteAccess(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	capability, err := deps.engine().DescribeExecutionSpecification(context.Background(), ExecutionSpecificationRequest{
		Target: "192.0.2.10", Protocol: ProtocolSSH,
	})
	if err != nil {
		t.Fatalf("DescribeExecutionSpecification() error = %v", err)
	}
	if capability.Target != "192.0.2.10" || capability.Protocol != ProtocolSSH || capability.PolicyVersion != policy.Version ||
		len(capability.DirectExecution) == 0 || !slices.Contains(capability.AbsoluteProhibitions, string(policy.ReasonFormatOrPartition)) ||
		capability.DefaultOutputBytes != 16<<10 {
		t.Fatalf("DescribeExecutionSpecification() = %#v", capability)
	}
	if deps.openedTUI != 0 || deps.sessions.touched != 0 || deps.ssh.calls != 0 || deps.database.queryCalls != 0 {
		t.Fatalf("DescribeExecutionSpecification() touched remote state: %#v", deps)
	}
}

func TestEngineDescribesDirectBinaryDeploymentCapabilityWithoutRemoteAccess(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	capability, err := deps.engine().DescribeExecutionSpecification(context.Background(), ExecutionSpecificationRequest{
		Target: "192.0.2.10", Protocol: ProtocolSSH,
	})
	if err != nil {
		t.Fatalf("DescribeExecutionSpecification() error = %v", err)
	}
	if !capability.BinaryDeploymentAvailable || !capability.AllowFileOperations || !capability.FileReadAvailable || capability.BinaryDeploymentDefaultBytes != sshtransport.DefaultBinaryDeploymentBytes ||
		capability.BinaryDeploymentMaxBytes != sshtransport.MaxBinaryDeploymentBytes ||
		capability.BinaryDeploymentDefaultTimeoutSeconds != int(DefaultBinaryDeploymentTimeout/time.Second) ||
		capability.BinaryDeploymentMaxTimeoutSeconds != int(MaxBinaryDeploymentTimeout/time.Second) ||
		!slices.Contains(capability.DirectExecution, "controlled_binary_deployment") {
		t.Fatalf("deployment capability = %#v", capability)
	}
	if deps.openedTUI != 0 || deps.sessions.touched != 0 || deps.ssh.calls != 0 || deps.database.queryCalls != 0 {
		t.Fatalf("DescribeExecutionSpecification() touched remote state: %#v", deps)
	}
}

func TestEngineDescribesRegisteredSQLCapabilityWithoutRemoteAccess(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	capability, err := deps.engine().DescribeExecutionSpecification(context.Background(), ExecutionSpecificationRequest{
		Target: "192.0.2.20:5432", Protocol: ProtocolSQL,
	})
	if err != nil {
		t.Fatalf("DescribeExecutionSpecification() error = %v", err)
	}
	if capability.Target != "192.0.2.20:5432" || capability.Protocol != ProtocolSQL ||
		len(capability.DirectExecution) == 0 || capability.MaxRows != 0 ||
		deps.openedTUI != 0 || deps.sessions.touched != 0 || deps.database.queryCalls != 0 {
		t.Fatalf("DescribeExecutionSpecification() = %#v, deps = %#v", capability, deps)
	}
}

func TestEngineOpensTUIWhenSSHTargetIsNotRegistered(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.sshErr = store.ErrTargetNotFound
	_, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.99", Command: "free -m"})
	if !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("RunSSH() error = %v, want ErrTargetNotFound", err)
	}
	if deps.openedTUI != 1 {
		t.Fatalf("RunSSH() did not open TUI for unregistered target: %#v", deps)
	}
}

func TestEngineOpensTUIWhenDatabaseTargetIsNotRegistered(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.databaseErr = store.ErrTargetNotFound
	_, err := deps.engine().RunSQL(context.Background(), SQLRequest{Target: "192.0.2.99:5432", Statement: "SELECT 1"})
	if !errors.Is(err, store.ErrTargetNotFound) {
		t.Fatalf("RunSQL() error = %v, want ErrTargetNotFound", err)
	}
	if deps.openedTUI != 1 {
		t.Fatalf("RunSQL() did not open TUI for unregistered target: %#v", deps)
	}
}

func TestEngineRequiresUnlockBeforeRemoteOperation(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.sessions.err = store.ErrLocked
	engine := deps.engine()
	result, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusUnlockRequired || deps.openedTUI != 1 || deps.ssh.calls != 0 || len(deps.audit.entries) != 1 ||
		deps.audit.entries[0].Result.Status != StatusUnlockRequired || deps.audit.entries[0].Phase != auditlog.PhaseDecision {
		t.Fatalf("locked RunSSH() = %#v, deps = %#v", result, deps)
	}
}

func TestEngineStopsRemoteDispatchAfterCredentialMigrationFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.db")
	credentialStore, err := store.Open(path)
	if err != nil {
		t.Fatalf("打开凭据库失败：%v", err)
	}
	vault, err := credentialStore.Initialize(context.Background(), []byte("migration-failure-master-password"))
	if err != nil {
		_ = credentialStore.Close()
		t.Fatalf("初始化凭据库失败：%v", err)
	}
	if err := vault.PutCredential(context.Background(), "legacy-ssh", "legacy", []byte("migration-failure-password")); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("写入旧凭据失败：%v", err)
	}
	if err := credentialStore.UpsertSSHTarget(context.Background(), store.SSHTarget{
		IP: "192.0.2.80", Mode: store.SSHDirect, LoginUsername: "ops", CredentialID: "legacy-ssh", Enabled: true,
	}); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("写入旧 SSH 登记目标失败：%v", err)
	}
	vault.Lock()
	if err := credentialStore.Close(); err != nil {
		t.Fatalf("关闭凭据库失败：%v", err)
	}

	legacy, err := sql.Open("sqlite", path+"?_pragma=foreign_keys%3don")
	if err != nil {
		t.Fatalf("打开旧数据库状态失败：%v", err)
	}
	if _, err := legacy.Exec("DELETE FROM credential_owners; UPDATE credentials SET ciphertext = X'00' WHERE id = 'legacy-ssh'"); err != nil {
		_ = legacy.Close()
		t.Fatalf("构造旧版迁移失败状态失败：%v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧数据库状态失败：%v", err)
	}

	credentialStore, err = store.Open(path)
	if err != nil {
		t.Fatalf("重新打开凭据库失败：%v", err)
	}
	defer credentialStore.Close()
	manager := session.NewManager(credentialStore)
	if _, err := manager.Unlock(context.Background(), []byte("migration-failure-master-password")); !errors.Is(err, store.ErrCredentialMigrationFailed) {
		t.Fatalf("解锁错误 = %v，期望 ErrCredentialMigrationFailed", err)
	}
	if manager.IsUnlocked() {
		t.Fatal("凭据迁移失败后会话仍处于解锁状态")
	}

	deps := newFakeDependencies()
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: manager, SSH: deps.ssh, Database: deps.database,
		WorkSessions: deps.workSessions, Audit: deps.audit,
		OpenTUI: deps.OpenTUI, SessionID: "migration-failure-test",
	})
	result, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() 错误 = %v", err)
	}
	if result.Status != StatusUnlockRequired || result.RemoteExecuted || deps.ssh.calls != 0 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("迁移失败后的派发结果 = %#v，SSH 调用 = %#v", result, deps.ssh)
	}
	sqlResult, err := engine.RunSQL(context.Background(), SQLRequest{
		Target: "192.0.2.20:5432", Statement: "SELECT 1",
	})
	if err != nil {
		t.Fatalf("RunSQL() 错误 = %v", err)
	}
	if sqlResult.Status != StatusUnlockRequired || sqlResult.RemoteExecuted || deps.database.queryCalls != 0 || deps.database.executeCalls != 0 {
		t.Fatalf("迁移失败后的 SQL 派发结果 = %#v，数据库调用 = %#v", sqlResult, deps.database)
	}
}

func TestEngineKeepsKnownExecutionOutcomeWhenTerminalAuditFails(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.audit.failAt = 2
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{
		Target: "192.0.2.10", Command: "free -m",
	})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || result.ExecutionOutcome != StatusCompleted || result.AuditOutcome != AuditOutcomeFailed || !result.RemoteExecuted {
		t.Fatalf("RunSSH() = %#v", result)
	}
}

func TestEngineKeepsKnownSQLExecutionOutcomeWhenTerminalAuditFails(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.audit.failAt = 2
	result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
		Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1",
	})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusCompleted || result.ExecutionOutcome != StatusCompleted || result.AuditOutcome != AuditOutcomeFailed || !result.RemoteExecuted {
		t.Fatalf("RunSQL() = %#v", result)
	}
}

func TestEngineBindsEphemeralStateToExecutionOwner(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	first := deps.engine().WithExecutionOwner("bridge-owner-a")
	second := deps.engine().WithExecutionOwner("bridge-owner-b")
	session, err := first.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil || session.Status != StatusSSHSessionOpened || session.Session == nil {
		t.Fatalf("OpenSSHSession() = %#v, %v", session, err)
	}
	foreignSession, err := second.SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{
		SessionID: session.Session.ID,
		Context:   SSHSessionContext{WorkingDirectory: "/", Environment: map[string]string{}},
	})
	if err != nil || foreignSession.Status != StatusSSHSessionNotFound {
		t.Fatalf("foreign SetSSHSessionContext() = %#v, %v", foreignSession, err)
	}
}

func TestEngineRunsBoundedLowRiskSSHAndAuditsWithoutPersistingOutput(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.ssh.result = sshtransport.ExecutionResult{Stdout: "password=should-not-leak", ExitStatus: 0, OutputTruncated: true}
	engine := deps.engine()
	result, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusOutcomeUnknown || result.ExecutionOutcome != StatusOutcomeUnknown || result.SSH == nil || result.SSH.Stdout != "password=should-not-leak" || !result.UntrustedRemoteOutput {
		t.Fatalf("RunSSH() = %#v", result)
	}
	if deps.ssh.calls != 1 || deps.ssh.isolatedCalls != 1 || deps.ssh.command != "free -m" || deps.ssh.timeout != policy.DefaultSSHTimeout || deps.sessions.touched != 1 {
		t.Fatalf("SSH call = %#v, sessions = %#v", deps.ssh, deps.sessions)
	}
	if len(deps.audit.entries) != 2 || deps.audit.entries[1].Policy.Decision != string(policy.DecisionAllowed) ||
		deps.audit.entries[1].Actor.BridgeSessionID != "mcp-session-test" || deps.audit.entries[1].OperationID == "" ||
		deps.audit.entries[1].SSHCommand != "free -m" || !deps.audit.entries[1].Result.OutputTruncated ||
		deps.audit.entries[1].Result.DurationMS == nil {
		t.Fatalf("audit entries = %#v", deps.audit.entries)
	}
}

func TestEngineReportsNotDispatchedWhenIsolatedSSHConnectionFailsBeforeCommandStart(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.ssh.err = fmt.Errorf("%w: authentication failed", sshtransport.ErrNotDispatched)
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusNotDispatched || result.RemoteExecuted || deps.ssh.calls != 1 || deps.ssh.isolatedCalls != 1 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
	last := deps.audit.entries[len(deps.audit.entries)-1]
	if last.Result.Status != StatusNotDispatched || last.RemoteExecuted {
		t.Fatalf("not-dispatched audit = %#v", last)
	}
}

func TestEngineRunsDFDiagnosticDirectly(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "df -h"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || deps.ssh.calls != 1 {
		t.Fatalf("df result = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineOpensAndUsesStructuredSSHWorkSession(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	engine := deps.engine()
	opened, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	if opened.Status != StatusSSHSessionOpened || opened.Session == nil || opened.Session.ID == "" {
		t.Fatalf("OpenSSHSession() = %#v", opened)
	}
	if deps.ssh.calls != 0 {
		t.Fatalf("OpenSSHSession() dispatched SSH: %#v", deps.ssh)
	}

	updated, err := engine.SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{
		SessionID: opened.Session.ID,
		Context: SSHSessionContext{
			WorkingDirectory: "/srv/app",
			Environment:      map[string]string{"APP_ENV": "production"},
		},
	})
	if err != nil {
		t.Fatalf("SetSSHSessionContext() error = %v", err)
	}
	if updated.Status != StatusSSHSessionContextUpdated || updated.Session == nil || updated.Session.Context.WorkingDirectory != "/srv/app" {
		t.Fatalf("SetSSHSessionContext() = %#v", updated)
	}

	result, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusCompleted || result.SSHSession == nil || result.SSHSession.ID != opened.Session.ID || deps.ssh.calls != 1 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
	if got, want := deps.ssh.command, "cd '/srv/app' && env 'APP_ENV=production' /bin/sh -c 'free -m'"; got != want {
		t.Fatalf("session SSH command = %q, want %q", got, want)
	}
}

func TestEngineKeepsSSHWorkSessionContextsIsolated(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	engine := deps.engine()
	first, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("first OpenSSHSession() error = %v", err)
	}
	second, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("second OpenSSHSession() error = %v", err)
	}
	for _, update := range []struct {
		id      string
		context SSHSessionContext
	}{
		{id: first.Session.ID, context: SSHSessionContext{WorkingDirectory: "/srv/one", Environment: map[string]string{"APP_ENV": "one"}}},
		{id: second.Session.ID, context: SSHSessionContext{WorkingDirectory: "/srv/two", Environment: map[string]string{"APP_ENV": "two"}}},
	} {
		if _, err := engine.SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{SessionID: update.id, Context: update.context}); err != nil {
			t.Fatalf("SetSSHSessionContext(%q) error = %v", update.id, err)
		}
	}
	for _, execution := range []struct {
		id   string
		want string
	}{
		{id: first.Session.ID, want: "cd '/srv/one' && env 'APP_ENV=one' /bin/sh -c 'free -m'"},
		{id: second.Session.ID, want: "cd '/srv/two' && env 'APP_ENV=two' /bin/sh -c 'free -m'"},
	} {
		if _, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: execution.id, Command: "free -m"}); err != nil {
			t.Fatalf("ExecuteSSHSession(%q) error = %v", execution.id, err)
		}
		if deps.ssh.command != execution.want {
			t.Fatalf("session %q command = %q, want %q", execution.id, deps.ssh.command, execution.want)
		}
	}
}

func TestEngineExpiresSSHWorkSessionWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 4, 9, 0, 0, 0, time.UTC)
	deps := newFakeDependencies()
	deps.workSessions = worksession.New(worksession.Options{Now: func() time.Time { return now }})
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	now = now.Add(worksession.DefaultIdleTimeout)
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusSSHSessionExpired || result.Decision != policy.DecisionRejected || deps.ssh.calls != 0 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineReportsSSHWorkSessionExpiredAfterIdleTimer(t *testing.T) {
	t.Parallel()

	expired := make(chan worksession.Session, 1)
	deps := newFakeDependencies()
	deps.workSessions = worksession.New(worksession.Options{
		IdleTimeout: 10 * time.Millisecond,
		OnInvalidated: func(session worksession.Session) {
			expired <- session
		},
	})
	engine := deps.engine()
	opened, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	select {
	case session := <-expired:
		if session.ID != opened.Session.ID {
			t.Fatalf("expired session = %#v, want %q", session, opened.Session.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH work session did not expire")
	}

	result, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusSSHSessionExpired || result.Decision != policy.DecisionRejected || deps.ssh.calls != 0 {
		t.Fatalf("ExecuteSSHSession() after idle timer = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineInvalidatesSSHWorkSessionWhenTargetRevisionChanges(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	deps.targets.sshTarget.Revision++
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusSSHSessionInvalidated || result.Decision != policy.DecisionRejected || deps.ssh.calls != 0 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineDirectlyExecutesOrdinarySSHWorkSessionCommand(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "mkdir -p /srv/app"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || result.SSHSession == nil || deps.ssh.calls != 1 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineDoesNotDispatchSSHWorkSessionAfterInvalidation(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	deps.audit.onRecord = func(event auditlog.Event) {
		if event.Phase == auditlog.PhaseStarted {
			deps.workSessions.Clear()
		}
	}
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusNotDispatched || result.RemoteExecuted || deps.ssh.calls != 0 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineAllowsRawSSHSessionCommandWithinStructuredContext(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	engine := deps.engine()
	opened, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	if _, err := engine.SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{
		SessionID: opened.Session.ID,
		Context:   SSHSessionContext{WorkingDirectory: "/srv/app", Environment: map[string]string{"APP_ENV": "production"}},
	}); err != nil {
		t.Fatalf("SetSSHSessionContext() error = %v", err)
	}
	result, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "cd /tmp"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession(cd) error = %v", err)
	}
	if result.Status != StatusCompleted || deps.ssh.calls != 1 {
		t.Fatalf("ExecuteSSHSession(cd) = %#v, ssh = %#v", result, deps.ssh)
	}
	if _, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"}); err != nil {
		t.Fatalf("ExecuteSSHSession(free) error = %v", err)
	}
	if got, want := deps.ssh.command, "cd '/srv/app' && env 'APP_ENV=production' /bin/sh -c 'free -m'"; got != want {
		t.Fatalf("session SSH command = %q, want %q", got, want)
	}
}

func TestEngineRejectsKnownRelativeSSHWorkSessionPathsWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		directory string
		command   string
		rule      policy.Reason
	}{
		{name: "base system directory", directory: "/etc", command: "rm -rf .", rule: policy.ReasonBaseSystemTreeDestruction},
		{name: "raw block destination", directory: "/dev", command: "printf x > sdb", rule: policy.ReasonRawBlockDeviceWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := newFakeDependencies()
			engine := deps.engine()
			opened, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
			if err != nil {
				t.Fatalf("OpenSSHSession() error = %v", err)
			}
			if _, err := engine.SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{
				SessionID: opened.Session.ID,
				Context:   SSHSessionContext{WorkingDirectory: test.directory, Environment: map[string]string{}},
			}); err != nil {
				t.Fatalf("SetSSHSessionContext() error = %v", err)
			}
			result, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: test.command})
			if err != nil {
				t.Fatalf("ExecuteSSHSession() error = %v", err)
			}
			if result.Status != StatusRejected || result.Decision != policy.DecisionPermanentlyRejected || result.Reason != test.rule || result.HandoffCommand == "" || result.RemoteExecuted || deps.ssh.calls != 0 {
				t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
			}
			if want := "cd '" + test.directory + "' &&"; !strings.Contains(result.HandoffCommand, want) {
				t.Fatalf("ExecuteSSHSession() handoff = %q, want declared working directory %q", result.HandoffCommand, want)
			}
		})
	}
}

func TestEngineRejectsUnsafeSSHWorkSessionContext(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	for _, sessionContext := range []SSHSessionContext{
		{WorkingDirectory: "relative", Environment: map[string]string{}},
		{WorkingDirectory: "/srv/app", Environment: map[string]string{"DEPLOY_TOKEN": "secret"}},
		{WorkingDirectory: "/srv/app", Environment: map[string]string{"PATH": "/tmp/bin"}},
	} {
		result, err := deps.engine().SetSSHSessionContext(context.Background(), SetSSHSessionContextRequest{SessionID: opened.Session.ID, Context: sessionContext})
		if err != nil {
			t.Fatalf("SetSSHSessionContext(%#v) error = %v", sessionContext, err)
		}
		if result.Status != StatusRejected || result.Decision != policy.DecisionRejected {
			t.Fatalf("SetSSHSessionContext(%#v) = %#v", sessionContext, result)
		}
	}
	if deps.ssh.calls != 0 {
		t.Fatalf("unsafe context reached SSH: %#v", deps.ssh)
	}
}

func TestEngineInvalidatesSSHWorkSessionWhenLocked(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	deps.sessions.err = store.ErrLocked
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusUnlockRequired || deps.ssh.calls != 0 {
		t.Fatalf("locked ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
	deps.sessions.err = nil
	result, err = deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("second ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusSSHSessionNotFound || deps.ssh.calls != 0 {
		t.Fatalf("second ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineInvalidatesSSHWorkSessionAfterOutcomeUnknown(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	opened, err := deps.engine().OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	deps.ssh.err = errors.New("SSH connection reset")
	result, err := deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusOutcomeUnknown || deps.ssh.calls != 1 {
		t.Fatalf("first ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
	deps.ssh.err = nil
	result, err = deps.engine().ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "free -m"})
	if err != nil {
		t.Fatalf("second ExecuteSSHSession() error = %v", err)
	}
	if result.Status != StatusSSHSessionNotFound || deps.ssh.calls != 1 {
		t.Fatalf("second ExecuteSSHSession() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineDirectlyExecutesOrdinarySSHWithoutReview(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "mkdir -p /data/app"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || deps.ssh.calls != 1 || !result.RemoteExecuted {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineRejectsTargetCommandBlacklistWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.sshTarget.CommandBlacklistPatterns = []string{"rm /data/.*"}
	engine := deps.engine()

	direct, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "rm /data/mysql"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if direct.Status != StatusRejected || direct.Decision != policy.DecisionRejected || direct.Reason != policy.ReasonTargetCommandBlacklist ||
		direct.RuleID != string(policy.ReasonTargetCommandBlacklist) || direct.MatchedFragment != "rm /data/.*" || direct.HandoffCommand != "" || direct.RemoteExecuted || deps.ssh.calls != 0 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", direct, deps.ssh)
	}
	for _, required := range []string{"命令黑名单", "当前用户请求任务链", "改写、变形或重试", "同一效果", "当前本地用户", "本地 TUI"} {
		if !strings.Contains(direct.Message, required) {
			t.Fatalf("RunSSH() message = %q, missing %q", direct.Message, required)
		}
	}
	if len(deps.audit.entries) != 1 || deps.audit.entries[0].Phase != auditlog.PhaseDecision || deps.audit.entries[0].RemoteExecuted || deps.audit.entries[0].Policy.Reason != string(policy.ReasonTargetCommandBlacklist) {
		t.Fatalf("direct blacklist audit = %#v", deps.audit.entries)
	}

	opened, err := engine.OpenSSHSession(context.Background(), OpenSSHSessionRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatalf("OpenSSHSession() error = %v", err)
	}
	fromSession, err := engine.ExecuteSSHSession(context.Background(), ExecuteSSHSessionRequest{SessionID: opened.Session.ID, Command: "rm /data/mysql"})
	if err != nil {
		t.Fatalf("ExecuteSSHSession() error = %v", err)
	}
	if fromSession.Status != StatusRejected || fromSession.Decision != policy.DecisionRejected || fromSession.Reason != policy.ReasonTargetCommandBlacklist ||
		fromSession.RuleID != string(policy.ReasonTargetCommandBlacklist) || fromSession.HandoffCommand != "" || fromSession.RemoteExecuted || deps.ssh.calls != 0 {
		t.Fatalf("ExecuteSSHSession() = %#v, ssh = %#v", fromSession, deps.ssh)
	}
}

func TestEngineAllowsNestedHopToRegisteredSSHIdentity(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.registeredSSHTargets = []store.SSHTarget{
		{IP: "192.0.2.10", SSHPort: 22, Enabled: true},
		{IP: "192.0.2.41", SSHPort: 2201, Enabled: true},
	}
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{
		Target: "192.0.2.10", Command: "ssh -p 2201 ops@192.0.2.41 uptime",
	})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || result.RuleID != "" || deps.ssh.calls != 1 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineRejectsNestedHopToUnregisteredSSHIdentity(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.registeredSSHTargets = []store.SSHTarget{{IP: "192.0.2.10", SSHPort: 22, Enabled: true}}
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{
		Target: "192.0.2.10", Command: "ssh 192.0.2.99 uptime",
	})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusRejected || result.Decision != policy.DecisionPermanentlyRejected ||
		result.RuleID != string(policy.ReasonUnregisteredRemoteHop) || result.HandoffCommand == "" || deps.ssh.calls != 0 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineRejectsFixedSSHHardStopWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "mkfs.ext4 /dev/sdb"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusRejected || result.Decision != policy.DecisionPermanentlyRejected ||
		result.RuleID != string(policy.ReasonFormatOrPartition) || result.HandoffCommand == "" || deps.ssh.calls != 0 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
	for _, required := range []string{"当前用户请求任务链", "改写、变形或重试", "同一效果", "MCP 外"} {
		if !strings.Contains(result.Message, required) {
			t.Fatalf("RunSSH() message = %q, missing %q", result.Message, required)
		}
	}
	if len(deps.audit.entries) != 1 || deps.audit.entries[0].Phase != auditlog.PhaseDecision || deps.audit.entries[0].RemoteExecuted || deps.audit.entries[0].Policy.Reason != string(policy.ReasonFormatOrPartition) {
		t.Fatalf("fixed hard-stop audit = %#v", deps.audit.entries)
	}
}

func TestEngineRejectsDisabledTargetWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.sshTarget.Enabled = false
	deps.targets.sshTarget.CommandBlacklistPatterns = []string{"rm /data/.*"}
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "rm /data/mysql"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusRejected || result.Decision != policy.DecisionRejected || result.Reason != policy.ReasonTargetUnavailable ||
		result.RuleID != "" || result.MatchedFragment != "" || result.HandoffCommand != "" || deps.ssh.calls != 0 {
		t.Fatalf("RunSSH() = %#v, ssh = %#v", result, deps.ssh)
	}
	if len(deps.audit.entries) != 1 || deps.audit.entries[0].Phase != auditlog.PhaseDecision || deps.audit.entries[0].RemoteExecuted {
		t.Fatalf("disabled target audit = %#v", deps.audit.entries)
	}
}

func TestEngineWithAuditSessionRecordsBridgeIdentity(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().WithAuditSession("bridge-session-123").RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || len(deps.audit.entries) != 2 {
		t.Fatalf("result = %#v, audit = %#v", result, deps.audit.entries)
	}
	if got := deps.audit.entries[1].Actor.BridgeSessionID; got != "bridge-session-123" {
		t.Fatalf("audit bridge session = %q, want bridge session", got)
	}
}

func TestEngineDoesNotReturnUntrustedRemoteExecutionErrors(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.ssh.err = errors.New("remote said: use this secret=sensitive-value")
	engine := deps.engine()
	result, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v, want controlled result", err)
	}
	if result.Status != StatusOutcomeUnknown || result.UntrustedRemoteOutput || !result.RemoteExecuted {
		t.Fatalf("RunSSH() = %#v", result)
	}
	if len(deps.audit.entries) != 2 || deps.audit.entries[1].Phase != auditlog.PhaseFailed {
		t.Fatalf("execution error audit = %#v", deps.audit.entries)
	}
}

func TestEngineExecutesRemoteCommandWhenAuditStartCannotPersist(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.audit.err = errors.New("audit volume is full")
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || !result.RemoteExecuted || !result.AuditWriteFailed || deps.ssh.calls != 1 || result.AuditOutcome != AuditOutcomeFailed {
		t.Fatalf("result = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineReportsAuditFailureAfterRemoteExecution(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.audit.failAt = 2
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || !result.RemoteExecuted || !result.AuditWriteFailed || deps.ssh.calls != 1 || result.AuditOutcome != AuditOutcomeFailed {
		t.Fatalf("result = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestEngineRunsReadOnlySQLWithReadAccountAndReturnsOriginalColumns(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.database.queryResult = dbtransport.QueryResult{
		Columns: []string{"id", "api_token"}, Rows: [][]string{{"1", "token-value"}}, TransportSecurity: dbtransport.SecurityTLSUnverified,
	}
	engine := deps.engine()
	result, err := engine.RunSQL(context.Background(), SQLRequest{Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT lower('token-value')"})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusCompleted || result.SQL == nil || result.SQL.Rows[0][1] != "token-value" || result.SQL.TransportSecurity != dbtransport.SecurityTLSUnverified {
		t.Fatalf("RunSQL() = %#v", result)
	}
	if deps.database.queryCalls != 1 || deps.database.queryTimeout != policy.DefaultSQLTimeout || deps.database.queryLimits.MaxRows != policy.DefaultMaxRows {
		t.Fatalf("database calls = %#v", deps.database)
	}
}

func TestEngineReturnsDatabaseListTruncationFact(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.database.listResult = dbtransport.DatabaseListResult{
		Databases: []string{"app", "metrics"}, OutputTruncated: true, TransportSecurity: dbtransport.SecurityTLSUnverified,
	}
	result, err := deps.engine().ListDatabases(context.Background(), DatabaseListRequest{Target: "192.0.2.20:5432"})
	if err != nil {
		t.Fatalf("ListDatabases() error = %v", err)
	}
	if result.Status != StatusCompleted || len(result.Databases) != 2 || !result.DatabasesTruncated || !result.RemoteExecuted {
		t.Fatalf("ListDatabases() = %#v", result)
	}
	if len(deps.audit.entries) != 2 || !deps.audit.entries[1].Result.OutputTruncated {
		t.Fatalf("list database audit = %#v", deps.audit.entries)
	}
}

func TestEngineBoundsTerminalAuditForDirectDatabaseOperations(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*Engine) (Result, error)
	}{
		{
			name: "只读 SQL",
			run: func(engine *Engine) (Result, error) {
				return engine.RunSQL(context.Background(), SQLRequest{Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1"})
			},
		},
		{
			name: "数据库列表",
			run: func(engine *Engine) (Result, error) {
				return engine.ListDatabases(context.Background(), DatabaseListRequest{Target: "192.0.2.20:5432"})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := newFakeDependencies()
			audit := &blockingTerminalAudit{}
			deps.auditor = audit
			started := time.Now()
			result, err := test.run(deps.engine())
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("直接数据库操作 error = %v", err)
			}
			if result.Status != StatusCompleted || !result.RemoteExecuted || !result.AuditWriteFailed || result.AuditOutcome != AuditOutcomeFailed {
				t.Fatalf("直接数据库操作结果 = %#v", result)
			}
			if elapsed > terminalAuditTimeout+time.Second {
				t.Fatalf("终态审计等待了 %s，超过一秒有界窗口", elapsed)
			}
			deadline, hasDeadline := audit.snapshot()
			if !hasDeadline || deadline < terminalAuditTimeout-200*time.Millisecond || deadline > terminalAuditTimeout {
				t.Fatalf("终态审计截止时间 = %s, hasDeadline = %v", deadline, hasDeadline)
			}
		})
	}
}

func TestEngineDirectlyExecutesOrdinaryWriteSQL(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
		Target: "192.0.2.20:5432", Database: "app", Statement: "UPDATE jobs SET state = 'ready' WHERE id = 1",
	})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || deps.database.executeCalls != 1 {
		t.Fatalf("direct write result = %#v, database = %#v", result, deps.database)
	}
	if got := deps.database.statementBatches; len(got) != 1 || len(got[0]) != 1 || got[0][0] != "UPDATE jobs SET state = 'ready' WHERE id = 1" {
		t.Fatalf("executed statements = %#v", got)
	}
}

func TestEngineDoesNotReportRemoteExecutionAfterTargetRevocation(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.ssh.err = store.ErrTargetChanged
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusNotDispatched || result.RemoteExecuted {
		t.Fatalf("RunSSH() = %#v", result)
	}
	if len(deps.audit.entries) < 2 || deps.audit.entries[len(deps.audit.entries)-1].RemoteExecuted || deps.audit.entries[len(deps.audit.entries)-1].Result.Status != StatusNotDispatched {
		t.Fatalf("audit entries = %#v", deps.audit.entries)
	}
}

func TestEngineDirectlyExecutesOrdinarySQLWithoutReview(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSQL(context.Background(), SQLRequest{Target: "192.0.2.20:5432", Database: "app", Statement: "UPDATE jobs SET state = 'ready' WHERE id = 1"})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || deps.database.queryCalls != 0 || len(deps.database.statementBatches) != 1 || !result.RemoteExecuted {
		t.Fatalf("RunSQL() = %#v, database = %#v", result, deps.database)
	}
}

type fakeDependencies struct {
	targets            *fakeTargets
	sessions           *fakeSessions
	ssh                *fakeSSH
	database           *fakeDatabase
	workSessions       *worksession.Store
	audit              *fakeAudit
	auditor            Auditor
	limiter            *policy.Limiter
	databaseAuthorizer *DatabaseTargetAuthorizer
	now                func() time.Time
	openedTUI          int
}

func newFakeDependencies() *fakeDependencies {
	return &fakeDependencies{
		targets: &fakeTargets{
			sshTarget:      store.SSHTarget{IP: "192.0.2.10", SSHPort: 22, LoginUsername: "ops", Enabled: true, AllowFileOperations: true, IdentityStatus: store.SSHIdentityVerified},
			databaseTarget: store.DatabaseInstance{Host: "192.0.2.20", Port: 5432, Engine: store.EnginePostgreSQL, DefaultDatabase: "app", ReadUsername: "app_read", ReadCredentialID: "read", WriteUsername: "app_write", WriteCredentialID: "write", Enabled: true, MajorVersion: 16, VersionStatus: store.DatabaseVersionVerified},
		}, sessions: &fakeSessions{}, ssh: &fakeSSH{}, database: &fakeDatabase{}, workSessions: worksession.New(worksession.Options{}), audit: &fakeAudit{},
	}
}

func (d *fakeDependencies) OpenTUI() error { d.openedTUI++; return nil }

func (d *fakeDependencies) engine() *Engine {
	auditor := Auditor(d.audit)
	if d.auditor != nil {
		auditor = d.auditor
	}
	return New(Dependencies{
		Targets: d.targets, Sessions: d.sessions, SSH: d.ssh, Database: d.database,
		WorkSessions: d.workSessions, Audit: auditor, Limiter: d.limiter, DatabaseAuthorizer: d.databaseAuthorizer, Now: d.now, OpenTUI: d.OpenTUI, SessionID: "mcp-session-test",
	})
}

type fakeTargets struct {
	sshErr                 error
	databaseErr            error
	waitForDatabaseContext bool
	registeredSSHTargets   []store.SSHTarget
	registeredSSHError     error
	sshTarget              store.SSHTarget
	databaseTarget         store.DatabaseInstance
}

func (f *fakeTargets) ListSSHTargets(context.Context) ([]store.SSHTarget, error) {
	if f.registeredSSHError != nil {
		return nil, f.registeredSSHError
	}
	if f.registeredSSHTargets != nil {
		return append([]store.SSHTarget(nil), f.registeredSSHTargets...), nil
	}
	return []store.SSHTarget{{IP: f.sshTarget.IP, SSHPort: f.sshTarget.SSHPort, Enabled: f.sshTarget.Enabled, AllowFileOperations: f.sshTarget.AllowFileOperations}}, nil
}
func (fakeTargets) ListDatabaseInstances(context.Context) ([]store.DatabaseInstance, error) {
	return []store.DatabaseInstance{{Host: "192.0.2.20", Port: 5432, Engine: store.EnginePostgreSQL, Enabled: true}}, nil
}
func (f *fakeTargets) SSHTarget(context.Context, string) (store.SSHTarget, error) {
	if f.sshErr != nil {
		return store.SSHTarget{}, f.sshErr
	}
	return f.sshTarget, nil
}
func (f *fakeTargets) DatabaseInstance(ctx context.Context, _ string, _ int) (store.DatabaseInstance, error) {
	if f.waitForDatabaseContext {
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			<-ctx.Done()
			return store.DatabaseInstance{}, ctx.Err()
		}
	}
	if f.databaseErr != nil {
		return store.DatabaseInstance{}, f.databaseErr
	}
	return f.databaseTarget, nil
}

type fakeSessions struct {
	err     error
	touched int
}

func (s *fakeSessions) Vault() (*store.Vault, error) { return nil, s.err }
func (s *fakeSessions) TouchRemoteActivity()         { s.touched++ }

type fakeSSH struct {
	result         sshtransport.ExecutionResult
	err            error
	waitForContext bool
	waitForRelease <-chan struct{}
	calls          int
	isolatedCalls  int
	command        string
	commands       []string
	asRoot         bool
	timeout        time.Duration
	onExecute      func()
}

func (s *fakeSSH) Execute(ctx context.Context, _ *store.Vault, _ store.SSHTarget, command string, asRoot bool, _ int) (sshtransport.ExecutionResult, error) {
	return s.execute(ctx, command, asRoot)
}

func (s *fakeSSH) ExecuteIsolated(ctx context.Context, _ *store.Vault, _ store.SSHTarget, _ string, command string, asRoot bool, _ int) (sshtransport.ExecutionResult, error) {
	s.isolatedCalls++
	return s.execute(ctx, command, asRoot)
}

func (s *fakeSSH) execute(ctx context.Context, command string, asRoot bool) (sshtransport.ExecutionResult, error) {
	s.calls++
	s.command = command
	s.commands = append(s.commands, command)
	s.asRoot = asRoot
	s.timeout = deadline(ctx)
	if s.onExecute != nil {
		s.onExecute()
	}
	if s.waitForContext {
		<-ctx.Done()
		return s.result, ctx.Err()
	}
	if s.waitForRelease != nil {
		<-s.waitForRelease
	}
	return s.result, s.err
}

type fakeDatabase struct {
	listResult       dbtransport.DatabaseListResult
	listCalls        int
	queryResult      dbtransport.QueryResult
	queryCalls       int
	queryTimeout     time.Duration
	queryLimits      dbtransport.Limits
	queryErr         error
	statementBatches [][]string
	executeCalls     int
	executeErr       error
	waitForContext   bool
	onExecute        func()
}

func (d *fakeDatabase) ListDatabases(context.Context, *store.Vault, store.DatabaseInstance) (dbtransport.DatabaseListResult, error) {
	d.listCalls++
	if d.listResult.TransportSecurity == "" {
		d.listResult.TransportSecurity = dbtransport.SecurityTLSUnverified
	}
	if d.listResult.Databases == nil {
		d.listResult.Databases = []string{"app"}
	}
	return d.listResult, nil
}
func (d *fakeDatabase) Query(ctx context.Context, _ *store.Vault, _ store.DatabaseInstance, _ string, _ string, limits dbtransport.Limits) (dbtransport.QueryResult, error) {
	d.queryCalls++
	d.queryTimeout = deadline(ctx)
	d.queryLimits = limits
	return d.queryResult, d.queryErr
}
func (d *fakeDatabase) ExecuteStatements(ctx context.Context, _ *store.Vault, _ store.DatabaseInstance, _ string, statements []string) (dbtransport.ExecutionResult, error) {
	d.executeCalls++
	if d.waitForContext {
		<-ctx.Done()
		return dbtransport.ExecutionResult{}, ctx.Err()
	}
	if d.executeErr != nil {
		return dbtransport.ExecutionResult{}, d.executeErr
	}
	d.statementBatches = append(d.statementBatches, append([]string(nil), statements...))
	if d.onExecute != nil {
		d.onExecute()
	}
	return dbtransport.ExecutionResult{AffectedRows: 1, TransportSecurity: dbtransport.SecurityTLSUnverified}, nil
}

type fakeAudit struct {
	entries  []auditlog.Event
	err      error
	failAt   int
	onRecord func(auditlog.Event)
}

type blockingTerminalAudit struct {
	mu          sync.Mutex
	deadline    time.Duration
	hasDeadline bool
}

func (a *blockingTerminalAudit) Record(ctx context.Context, entry auditlog.Event) error {
	if !entry.RemoteExecuted {
		return nil
	}
	deadline, hasDeadline := ctx.Deadline()
	a.mu.Lock()
	a.deadline = time.Until(deadline)
	a.hasDeadline = hasDeadline
	a.mu.Unlock()
	if !hasDeadline {
		time.Sleep(3 * time.Second)
		return errors.New("终态审计没有截止时间")
	}
	<-ctx.Done()
	return ctx.Err()
}

func (a *blockingTerminalAudit) snapshot() (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadline, a.hasDeadline
}

func (a *fakeAudit) Record(_ context.Context, entry auditlog.Event) error {
	if a.failAt > 0 && len(a.entries)+1 == a.failAt {
		return errors.New("audit volume is full")
	}
	a.entries = append(a.entries, entry)
	if a.onRecord != nil {
		a.onRecord(entry)
	}
	return a.err
}

func deadline(ctx context.Context) time.Duration {
	value, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(value).Round(time.Second)
}
func contains(value, fragment string) bool { return strings.Contains(value, fragment) }
