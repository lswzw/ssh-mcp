package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/store"
)

func TestEngineDirectExecutionAndAuditOutcomesAreIndependent(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.audit.err = errors.New("审计存储不可用")
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{
		Target: "192.0.2.10", Command: "mkdir -p /data/app",
	})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status != StatusCompleted || result.ExecutionOutcome != StatusCompleted ||
		result.AuditOutcome != AuditOutcomeFailed || !result.AuditWriteFailed || !result.RemoteExecuted || deps.ssh.calls != 1 {
		t.Fatalf("直接执行遇到审计失败 = %#v，SSH = %#v", result, deps.ssh)
	}
}

func TestEngineUnverifiedDatabaseVersionDoesNotGateSQL(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		statement string
		wantQuery bool
	}{
		{name: "查询", statement: "SELECT 1", wantQuery: true},
		{name: "带条件写入", statement: "UPDATE jobs SET state = 'ready' WHERE id = 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := newFakeDependencies()
			deps.targets.databaseTarget.VersionStatus = store.DatabaseVersionUnverified
			deps.targets.databaseTarget.MajorVersion = 0
			result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
				Target: "192.0.2.20:5432", Database: "app", Statement: test.statement,
			})
			if err != nil {
				t.Fatalf("RunSQL() error = %v", err)
			}
			if result.Status != StatusCompleted || result.Decision != policy.DecisionAllowed || !result.RemoteExecuted {
				t.Fatalf("版本未验证的 SQL 结果 = %#v，数据库 = %#v", result, deps.database)
			}
			if test.wantQuery && deps.database.queryCalls != 1 {
				t.Fatalf("查询没有直接派发：%#v", deps.database)
			}
			if !test.wantQuery && deps.database.executeCalls != 1 {
				t.Fatalf("写入没有直接派发：%#v", deps.database)
			}
		})
	}
}

func TestEngineDispatchesPreviouslyBlockedDestructiveCommands(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSSH(context.Background(), SSHRequest{
		Target: "192.0.2.10", Command: "mkfs.ext4 /dev/sdb",
	})
	if err != nil {
		t.Fatalf("RunSSH() error = %v", err)
	}
	if result.Status == StatusRejected || result.RuleID != "" || result.HandoffCommand != "" {
		t.Fatalf("硬拦截仍生效 = %#v", result)
	}
	if deps.ssh.calls != 1 || deps.ssh.command != "mkfs.ext4 /dev/sdb" {
		t.Fatalf("SSH 未派发 = %#v", deps.ssh)
	}
	if len(deps.audit.entries) == 0 || !deps.audit.entries[len(deps.audit.entries)-1].RemoteExecuted {
		t.Fatalf("审计未记录远端执行 = %#v", deps.audit.entries)
	}
}

func TestEngineDispatchesPreviouslyBlockedSQLStatements(t *testing.T) {
	t.Parallel()

	for _, statement := range []string{"DROP TABLE jobs", "DELETE FROM jobs", "TRUNCATE jobs"} {
		deps := newFakeDependencies()
		result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
			Target: "192.0.2.20:5432", Database: "app", Statement: statement,
		})
		if err != nil {
			t.Fatalf("RunSQL(%q) error = %v", statement, err)
		}
		if result.Status == StatusRejected || result.RuleID != "" || result.HandoffCommand != "" {
			t.Fatalf("SQL(%q) 仍被拦截 = %#v", statement, result)
		}
		if deps.database.executeCalls != 1 {
			t.Fatalf("SQL(%q) 未派发 = %#v", statement, deps.database)
		}
	}
}

func TestResultMessageExplainsHardStopsAndUnknownOutcomesInChinese(t *testing.T) {
	t.Parallel()

	if message := ResultMessage(StatusOutcomeUnknown, "", policy.DecisionAllowed, policy.ReasonStaticShell); !strings.Contains(message, "核验") {
		t.Fatalf("结果未知说明 = %q", message)
	}
}

func TestEngineReportsKnownSQLServerFailuresWithoutRawErrorText(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.database.queryErr = &pgconn.PgError{Code: "42601", Message: "secret text must not leave the driver"}
	result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
		Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1",
	})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusFailed || result.ExecutionOutcome != ExecutionOutcomeFailedKnown ||
		result.FailureKind != dbtransport.FailureKindSyntax || !result.RemoteExecuted ||
		strings.Contains(result.Message, "secret text") {
		t.Fatalf("已知 SQL 失败 = %#v", result)
	}
}
