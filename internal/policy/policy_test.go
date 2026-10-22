package policy

import (
	"context"
	"reflect"
	"testing"
	"time"

	"ssh-mcp/internal/store"
)

func TestHardStopRuleIDsIsEmptyInThisFork(t *testing.T) {
	t.Parallel()
	if got := HardStopRuleIDs(); len(got) != 0 {
		t.Fatalf("HardStopRuleIDs() = %#v, want empty", got)
	}
}

func TestSafetyNoticeIsNonEmptyAndStable(t *testing.T) {
	t.Parallel()
	notice := SafetyNotice()
	if len(notice) < 4 {
		t.Fatalf("SafetyNotice() = %#v, want at least four risk facts", notice)
	}
	for _, line := range notice {
		if line == "" {
			t.Fatalf("SafetyNotice() contains an empty line: %#v", notice)
		}
	}
	if !reflect.DeepEqual(SafetyNotice(), notice) {
		t.Fatal("SafetyNotice() is not stable between calls")
	}
}

// The whole point of this fork: semantic rules no longer stop anything.
func TestEvaluateSSHNeverBlocksSemanticRules(t *testing.T) {
	t.Parallel()
	commands := []string{
		"rm -rf /",
		"rm -rf /*",
		"mkfs.ext4 /dev/sda1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"fdisk /dev/sda",
		"shutdown -h now",
		"reboot",
		":(){ :|:& };:",
		"while true; do :; done",
		"chmod -R 000 /etc",
		"chown -R nobody /usr",
		"ssh root@203.0.113.9 'rm -rf /srv'",
		"eval \"$USER_INPUT\"",
		"cat /etc/passwd | sh",
		"truncate -s 0 /var/log/syslog",
	}
	for _, command := range commands {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionAllowed {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct execution", command, result)
		}
		if result.RuleID != "" || result.MatchedFragment != "" {
			t.Errorf("EvaluateSSH(%q) still reports rule %q", command, result.RuleID)
		}
	}
}

func TestEvaluateSSHRejectsInvalidWorkingDirectory(t *testing.T) {
	t.Parallel()
	for _, directory := range []string{"srv/app", "/srv/../app", "/srv//app"} {
		if result := EvaluateSSH(SSHRequest{Command: "ls", WorkingDirectory: directory}); result.Decision != DecisionRejected || result.Reason != ReasonInvalidRequest {
			t.Errorf("EvaluateSSH(working_directory=%q) = %#v, want invalid_request", directory, result)
		}
	}
	if result := EvaluateSSH(SSHRequest{Command: "   "}); result.Decision != DecisionRejected || result.Reason != ReasonInvalidRequest {
		t.Errorf("EvaluateSSH(empty) = %#v, want invalid_request", result)
	}
}

func TestEvaluateSSHStillHonorsTargetCommandBlacklist(t *testing.T) {
	t.Parallel()
	result := EvaluateSSH(SSHRequest{Command: "systemctl restart nginx", CommandBlacklistPatterns: []string{`restart\s+nginx`}})
	if result.Decision != DecisionRejected || result.Reason != ReasonTargetCommandBlacklist || result.RuleID != string(ReasonTargetCommandBlacklist) {
		t.Fatalf("blacklisted command = %#v", result)
	}
	if result.MatchedFragment != `restart\s+nginx` {
		t.Fatalf("matched fragment = %q", result.MatchedFragment)
	}
	for _, pattern := range []string{"", "[", "("} {
		if result := EvaluateSSH(SSHRequest{Command: "ls", CommandBlacklistPatterns: []string{pattern}}); result.Decision != DecisionRejected || result.Reason != ReasonInvalidRequest {
			t.Errorf("EvaluateSSH(pattern=%q) = %#v, want invalid_request", pattern, result)
		}
	}
	// A blacklist match also applies when local shell parsing fails.
	if result := EvaluateSSH(SSHRequest{Command: "echo 'unterminated", CommandBlacklistPatterns: []string{"echo"}}); result.Decision != DecisionRejected || result.Reason != ReasonTargetCommandBlacklist {
		t.Errorf("blacklist on unparsable command = %#v", result)
	}
}

func TestEvaluateSSHDefaultsToDirectForOrdinaryOperations(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"free -m", "df -h", "systemctl status nginx", "mysql -e 'show databases'", "sed -n '1,20p' /var/log/syslog"} {
		if result := EvaluateSSH(SSHRequest{Command: command}); result.Decision != DecisionAllowed || result.Reason != ReasonStaticShell {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct", command, result)
		}
	}
}

func TestInteractiveInputIsCapabilitySignal(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"read value", "vi /tmp/note", "top", "sh", "psql"} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionAllowed || !result.InteractiveInputRequired {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct interactive signal", command, result)
		}
	}
	for _, command := range []string{"sh -c 'echo ready'", "top -b -n 1", "sudo systemctl status mysql"} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.InteractiveInputRequired {
			t.Errorf("EvaluateSSH(%q) unexpectedly requires interactive input", command)
		}
	}
}

func TestLiteralSudoRequestsNonInteractiveExecution(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"sudo systemctl restart mysql", "env FOO=1 sudo ls", "command sudo id"} {
		if result := EvaluateSSH(SSHRequest{Command: command}); !result.UseNonInteractiveSudo {
			t.Errorf("EvaluateSSH(%q) = %#v, want non-interactive sudo", command, result)
		}
	}
	for _, command := range []string{"echo sudo", "ls /sudo"} {
		if result := EvaluateSSH(SSHRequest{Command: command}); result.UseNonInteractiveSudo {
			t.Errorf("EvaluateSSH(%q) = %#v, unexpected non-interactive sudo", command, result)
		}
	}
}

func TestEvaluateSQLNeverBlocksSemanticRules(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		engine     store.DatabaseEngine
		statement  string
		wantClass  SQLExecutionClass
		wantReason Reason
	}{
		{store.EngineMySQL, "DROP TABLE users", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EngineMySQL, "TRUNCATE TABLE users", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EngineMySQL, "ALTER TABLE users DROP COLUMN email", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EngineMySQL, "DELETE FROM users", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EngineMySQL, "UPDATE users SET admin = 1 WHERE 1 = 1", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EngineMySQL, "SELECT * FROM users", SQLExecutionRead, ReasonDiagnostic},
		{store.EnginePostgreSQL, "DROP TABLE users", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EnginePostgreSQL, "TRUNCATE users", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EnginePostgreSQL, "UPDATE users SET admin = true", SQLExecutionMayWrite, ReasonDiagnostic},
		{store.EnginePostgreSQL, "SELECT 1", SQLExecutionRead, ReasonDiagnostic},
	} {
		result := EvaluateSQL(SQLRequest{Engine: test.engine, Statement: test.statement})
		if result.Decision != DecisionAllowed {
			t.Errorf("EvaluateSQL(%q) = %#v, want direct execution", test.statement, result)
		}
		if result.ExecutionClass != test.wantClass {
			t.Errorf("EvaluateSQL(%q) class = %q, want %q", test.statement, result.ExecutionClass, test.wantClass)
		}
		if result.RuleID != "" {
			t.Errorf("EvaluateSQL(%q) still reports rule %q", test.statement, result.RuleID)
		}
	}
}

func TestSQLCredentialRouteIsConservativeWithoutBlocking(t *testing.T) {
	t.Parallel()
	if result := EvaluateSQL(SQLRequest{Engine: store.EngineMySQL, Statement: "WITH x AS (SELECT 1) SELECT * FROM x"}); result.ExecutionClass != SQLExecutionRead {
		t.Errorf("CTE select class = %q, want read_query", result.ExecutionClass)
	}
	if result := EvaluateSQL(SQLRequest{Engine: store.EngineMySQL, Statement: "not sql at all"}); result.Decision != DecisionAllowed || result.ExecutionClass != SQLExecutionMayWrite {
		t.Errorf("unparsable statement = %#v, want may_write direct", result)
	}
}

func TestExplicitFiniteLimitsReachTransport(t *testing.T) {
	t.Parallel()
	result := EvaluateSSH(SSHRequest{Command: "free -m", Timeout: 3 * time.Minute, MaxBytes: 2 << 20})
	if result.Timeout != 3*time.Minute || result.MaxBytes != 2<<20 {
		t.Fatalf("EvaluateSSH() limits = %v/%d", result.Timeout, result.MaxBytes)
	}
	sql := EvaluateSQL(SQLRequest{Engine: store.EnginePostgreSQL, Statement: "SELECT 1", Timeout: 2 * time.Minute, MaxRows: 5000, MaxBytes: 1 << 20})
	if sql.Timeout != 2*time.Minute || sql.MaxRows != 5000 || sql.MaxBytes != 1<<20 {
		t.Fatalf("EvaluateSQL() limits = %v/%d/%d", sql.Timeout, sql.MaxRows, sql.MaxBytes)
	}
}

func TestDefaultsMatchDocumentedBudgets(t *testing.T) {
	t.Parallel()
	if DefaultSSHTimeout != 300*time.Second {
		t.Fatalf("DefaultSSHTimeout = %v, want 300s", DefaultSSHTimeout)
	}
	if DefaultSQLTimeout != 30*time.Second {
		t.Fatalf("DefaultSQLTimeout = %v, want 30s", DefaultSQLTimeout)
	}
	if DefaultMaxBytes != 64<<10 {
		t.Fatalf("DefaultMaxBytes = %d, want 65536", DefaultMaxBytes)
	}
	if DefaultMaxRows != 1000 {
		t.Fatalf("DefaultMaxRows = %d, want 1000", DefaultMaxRows)
	}
}

func TestSplitStatementsRemainsDialectAware(t *testing.T) {
	t.Parallel()
	for _, engine := range []store.DatabaseEngine{store.EngineMySQL, store.EnginePostgreSQL} {
		statements, err := SplitStatements(engine, "SELECT 'a;b'; SELECT 2")
		if err != nil || len(statements) != 2 {
			t.Errorf("SplitStatements(%q) = %#v, %v; want two statements", engine, statements, err)
		}
	}
}

func TestLimiterRejectsNonDirectDecision(t *testing.T) {
	t.Parallel()
	limiter := NewLimiter(1)
	if _, err := limiter.Acquire(context.Background(), DecisionRejected); err == nil {
		t.Fatal("Acquire(DecisionRejected) returned nil error")
	}
	release, err := limiter.Acquire(context.Background(), DecisionAllowed)
	if err != nil || release == nil {
		t.Fatalf("Acquire(DecisionAllowed) err = %v, release nil = %t", err, release == nil)
	}
	release()
}
