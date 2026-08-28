package policy

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"ssh-mcp/internal/store"
)

func TestHardStopRuleIDsAreFixedAndOrdered(t *testing.T) {
	want := []string{
		"format_or_partition",
		"raw_block_device_write",
		"base_system_tree_destruction",
		"unbounded_resource_exhaustion",
		"opaque_shell_effect",
		"opaque_sql_effect",
		"drop_database_schema_table",
		"truncate_table",
		"alter_drop",
		"unconditional_update_or_delete",
		"unregistered_remote_hop",
	}
	if got := HardStopRuleIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("HardStopRuleIDs() = %#v, want %#v", got, want)
	}
	copy := HardStopRuleIDs()
	copy[0] = "changed"
	if got := HardStopRuleIDs()[0]; got != want[0] {
		t.Fatalf("HardStopRuleIDs returned a mutable registry: %q", got)
	}
}

func TestEvaluateSSHHardStops(t *testing.T) {
	tests := []struct {
		name    string
		request SSHRequest
		rule    Reason
	}{
		{name: "format", request: SSHRequest{Command: "mkfs.ext4 /dev/sdb"}, rule: ReasonFormatOrPartition},
		{name: "raw block write", request: SSHRequest{Command: "dd if=/dev/zero of=/dev/sdb count=1"}, rule: ReasonRawBlockDeviceWrite},
		{name: "base system tree", request: SSHRequest{Command: "sudo rm -rf /usr/bin"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "base system root", request: SSHRequest{Command: "rm -rf /usr"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "kernel virtual filesystem", request: SSHRequest{Command: "rm -rf /dev"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "unbounded generator", request: SSHRequest{Command: "yes >/dev/null"}, rule: ReasonUnboundedResource},
		{name: "opaque shell stdin", request: SSHRequest{Command: "base64 -d payload | sh"}, rule: ReasonOpaqueShellEffect},
		{name: "nested ssh tunnel", request: SSHRequest{Command: "ssh -L 15432:db:5432 bastion"}, rule: ReasonUnregisteredRemoteHop},
		{name: "scp", request: SSHRequest{Command: "scp backup.sql host:/tmp/"}, rule: ReasonUnregisteredRemoteHop},
		{name: "sftp", request: SSHRequest{Command: "sftp host"}, rule: ReasonUnregisteredRemoteHop},
		{name: "rsync remote destination", request: SSHRequest{Command: "rsync -a ./build/ deploy@host:/srv/app/"}, rule: ReasonUnregisteredRemoteHop},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateSSH(test.request)
			if result.Decision != DecisionPermanentlyRejected || result.Reason != test.rule || result.RuleID != string(test.rule) || result.Risk != RiskHigh {
				t.Fatalf("EvaluateSSH(%q) = %#v, want hard stop %q", test.request.Command, result, test.rule)
			}
			if result.MatchedFragment == "" {
				t.Fatal("hard stop did not expose a matched fragment")
			}
		})
	}
}

func TestEvaluateSSHHardStopsKnownRelativePaths(t *testing.T) {
	tests := []struct {
		name    string
		request SSHRequest
		rule    Reason
	}{
		{name: "work session base system directory", request: SSHRequest{Command: "rm -rf .", WorkingDirectory: "/etc"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "work session raw block destination", request: SSHRequest{Command: "dd if=/dev/zero of=sdb count=1", WorkingDirectory: "/dev"}, rule: ReasonRawBlockDeviceWrite},
		{name: "work session output redirect", request: SSHRequest{Command: "printf x > sdb", WorkingDirectory: "/dev"}, rule: ReasonRawBlockDeviceWrite},
		{name: "literal cd base system directory", request: SSHRequest{Command: "cd /etc && rm -rf ."}, rule: ReasonBaseSystemTreeDestruction},
		{name: "literal cd raw block destination", request: SSHRequest{Command: "cd /dev && printf x > sdb"}, rule: ReasonRawBlockDeviceWrite},
		{name: "literal cd parent base system directory", request: SSHRequest{Command: "cd /tmp && rm -rf ../etc"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "relative literal cd from work session", request: SSHRequest{Command: "cd ../etc && rm -rf .", WorkingDirectory: "/tmp"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "literal embedded shell inherits directory", request: SSHRequest{Command: "cd /etc && sh -c 'rm -rf .'"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "embedded shell derives literal cd", request: SSHRequest{Command: "sh -c 'cd /etc && rm -rf .'"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "embedded shell combined options derives literal cd", request: SSHRequest{Command: "sh -ec 'cd /etc && rm -rf .'"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "embedded shell through exec derives literal cd", request: SSHRequest{Command: "exec sh -c 'cd /etc && find . -delete'"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "embedded shell through exec option terminator derives literal cd", request: SSHRequest{Command: "exec -- sh -c 'cd /etc && find . -delete'"}, rule: ReasonBaseSystemTreeDestruction},
		{name: "wrapper output redirect uses parent directory", request: SSHRequest{Command: "env --chdir=/tmp printf x > sdb", WorkingDirectory: "/dev"}, rule: ReasonRawBlockDeviceWrite},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateSSH(test.request)
			if result.Decision != DecisionPermanentlyRejected || result.Reason != test.rule || result.RuleID != string(test.rule) {
				t.Fatalf("EvaluateSSH(%q) = %#v, want hard stop %q", test.request.Command, result, test.rule)
			}
		})
	}
}

func TestEvaluateSSHLeavesUnknownRelativePathContextDirect(t *testing.T) {
	for _, request := range []SSHRequest{
		{Command: "rm -rf ."},
		{Command: "rm -rf .", WorkingDirectory: "/tmp"},
		{Command: "cd /etc; rm -rf ."},
		{Command: "cd /etc || rm -rf ."},
		{Command: "cd /etc | rm -rf ."},
		{Command: "if true; then cd /etc && rm -rf .; fi"},
		{Command: "cd - && rm -rf ."},
		{Command: "cd /tmp; rm -rf .", WorkingDirectory: "/etc"},
		{Command: "cd /tmp || rm -rf .", WorkingDirectory: "/etc"},
		{Command: "if true; then cd /tmp; fi; rm -rf .", WorkingDirectory: "/etc"},
		{Command: "if true; then rm -rf .; fi", WorkingDirectory: "/etc"},
		{Command: "! cd /definitely-missing && rm -rf .", WorkingDirectory: "/etc"},
		{Command: "command cd /tmp && rm -rf .", WorkingDirectory: "/etc"},
		{Command: "cd() { command cd /etc; }; cd /tmp && rm -rf .", WorkingDirectory: "/etc"},
		{Command: "builtin rm -rf /etc"},
		{Command: "env --chdir=/tmp find . -delete", WorkingDirectory: "/etc"},
		{Command: "env -C /tmp find . -delete", WorkingDirectory: "/etc"},
		{Command: "sudo --chdir /tmp find . -delete", WorkingDirectory: "/etc"},
		{Command: "exec -- env --chdir=/tmp find . -delete", WorkingDirectory: "/etc"},
		{Command: "pushd /tmp && find . -delete", WorkingDirectory: "/etc"},
		{Command: "trap 'cd /etc' USR1 && find . -delete", WorkingDirectory: "/tmp"},
	} {
		result := EvaluateSSH(request)
		if result.Decision != DecisionAllowed || result.RuleID != "" {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct", request.Command, result)
		}
	}
}

func TestCollectKnownPathCommandsDoesNotResolveUncertainCDOperands(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "CDPATH lookup", command: "export CDPATH=/ && cd etc && find . -delete"},
		{name: "unquoted glob", command: "cd /tmp/* && find . -delete"},
		{name: "builtin cd wrapper", command: "builtin cd /etc && find . -delete"},
		{name: "command cd option terminator", command: "command -- cd /etc && find . -delete"},
		{name: "builtin cd option terminator", command: "builtin -- cd /etc && find . -delete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := collectKnownPathCommands(test.command, "/tmp")
			for _, command := range commands {
				index := executableIndex(command.tokens)
				if index >= 0 && command.tokens[index] == "find" {
					t.Fatalf("collectKnownPathCommands(%q) inferred find context %#v", test.command, command)
				}
			}
		})
	}
}

func TestEvaluateSSHHardStopsKnownGroupedOutputRedirects(t *testing.T) {
	for _, command := range []string{
		"cd /dev && (printf x) > sdb",
		"cd /dev && { printf x; } > sdb",
	} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonRawBlockDeviceWrite {
			t.Errorf("EvaluateSSH(%q) = %#v, want raw block device hard stop", command, result)
		}
	}
}

func TestEvaluateSSHRejectsInvalidWorkingDirectory(t *testing.T) {
	for _, directory := range []string{"relative", "/etc/..", "/etc/./", "\x00/etc", "/tmp\nas_root=true", "/tmp\rnext"} {
		result := EvaluateSSH(SSHRequest{Command: "echo ready", WorkingDirectory: directory})
		if result.Decision != DecisionRejected || result.Reason != ReasonInvalidRequest {
			t.Errorf("EvaluateSSH(%q) = %#v, want invalid request", directory, result)
		}
	}
}

func TestEvaluateSSHRejectsTargetCommandBlacklistMatches(t *testing.T) {
	patterns := []string{"rm /data/.*", "cat /etc/passwd", "passwd.*", "^"}
	for _, test := range []struct {
		name    string
		command string
		pattern string
	}{
		{name: "data path", command: "rm /data/mysql", pattern: "rm /data/.*"},
		{name: "sensitive file", command: "cat /etc/passwd", pattern: "cat /etc/passwd"},
		{name: "password command", command: "passwd deploy", pattern: "passwd.*"},
		{name: "empty regex match", command: "echo ready", pattern: "^"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateSSH(SSHRequest{Command: test.command, CommandBlacklistPatterns: patterns})
			if result.Decision != DecisionRejected || result.Reason != ReasonTargetCommandBlacklist || result.RuleID != string(ReasonTargetCommandBlacklist) || result.MatchedFragment != test.pattern || result.Risk != RiskHigh {
				t.Fatalf("EvaluateSSH(%q) = %#v, want target command blacklist match %q", test.command, result, test.pattern)
			}
		})
	}
}

func TestEvaluateSSHTargetCommandBlacklistAppliesToInvalidShellSyntax(t *testing.T) {
	result := EvaluateSSH(SSHRequest{Command: "if then", CommandBlacklistPatterns: []string{"if then"}})
	if result.Decision != DecisionRejected || result.Reason != ReasonTargetCommandBlacklist || result.MatchedFragment != "if then" {
		t.Fatalf("EvaluateSSH() = %#v, want target command blacklist rejection", result)
	}
}

func TestEvaluateSSHFixedHardStopTakesPriorityOverTargetCommandBlacklist(t *testing.T) {
	result := EvaluateSSH(SSHRequest{Command: "mkfs.ext4 /dev/sdb", CommandBlacklistPatterns: []string{"mkfs.*"}})
	if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonFormatOrPartition || result.RuleID != string(ReasonFormatOrPartition) {
		t.Fatalf("EvaluateSSH() = %#v, want fixed hard stop", result)
	}
}

func TestEvaluateSSHRejectsInvalidTargetCommandBlacklist(t *testing.T) {
	result := EvaluateSSH(SSHRequest{Command: "echo ready", CommandBlacklistPatterns: []string{"["}})
	if result.Decision != DecisionRejected || result.Reason != ReasonInvalidRequest {
		t.Fatalf("EvaluateSSH() = %#v, want invalid request", result)
	}
}

func TestEvaluateSSHAllowsOnlyRegisteredStaticRemoteHops(t *testing.T) {
	registered := []RegisteredRemoteTarget{
		{Host: "192.0.2.40", Port: 22},
		{Host: "192.0.2.41", Port: 2201},
	}
	for _, command := range []string{
		"ssh ops@192.0.2.40 uptime",
		"ssh -p 2201 ops@192.0.2.41 uptime",
		"scp ./backup.sql ops@192.0.2.40:/tmp/backup.sql",
		"sftp -P 2201 ops@192.0.2.41",
		"rsync -az ./build/ ops@192.0.2.40:/srv/app/",
		"ssh -L 15432:192.0.2.40:22 192.0.2.40",
	} {
		t.Run(command, func(t *testing.T) {
			result := EvaluateSSH(SSHRequest{
				Command:                       command,
				RegisteredRemoteTargets:       registered,
				RemoteTargetRegistryAvailable: true,
			})
			if result.Decision != DecisionAllowed || result.RuleID != "" {
				t.Fatalf("EvaluateSSH(%q) = %#v, want direct", command, result)
			}
		})
	}
}

func TestEvaluateSSHRejectsUnknownNestedRemoteHops(t *testing.T) {
	registered := []RegisteredRemoteTarget{{Host: "192.0.2.40", Port: 22}}
	for _, test := range []struct {
		command string
		rule    Reason
	}{
		{command: "ssh -p 2201 192.0.2.40 uptime", rule: ReasonUnregisteredRemoteHop},
		{command: "ssh 192.0.2.99 uptime", rule: ReasonUnregisteredRemoteHop},
		{command: `ssh "$DESTINATION" uptime`, rule: ReasonOpaqueShellEffect},
		{command: "ssh -L 15432:192.0.2.99:22 192.0.2.40", rule: ReasonUnregisteredRemoteHop},
		{command: "scp ./backup.sql ops@bastion:/tmp/backup.sql", rule: ReasonUnregisteredRemoteHop},
	} {
		t.Run(test.command, func(t *testing.T) {
			result := EvaluateSSH(SSHRequest{
				Command:                       test.command,
				RegisteredRemoteTargets:       registered,
				RemoteTargetRegistryAvailable: true,
			})
			if result.Decision != DecisionPermanentlyRejected || result.Reason != test.rule || result.RuleID != string(test.rule) || result.MatchedFragment == "" {
				t.Fatalf("EvaluateSSH(%q) = %#v, want hard stop %q", test.command, result, test.rule)
			}
		})
	}
}

func TestEvaluateSSHDoesNotLetNestedRemoteHopMaskOpaqueShell(t *testing.T) {
	result := EvaluateSSH(SSHRequest{
		Command:                       `ssh 192.0.2.40 "$(date +%s)"`,
		RegisteredRemoteTargets:       []RegisteredRemoteTarget{{Host: "192.0.2.40", Port: 22}},
		RemoteTargetRegistryAvailable: true,
	})
	if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonOpaqueShellEffect || result.RuleID != string(ReasonOpaqueShellEffect) {
		t.Fatalf("EvaluateSSH() = %#v, want opaque-shell hard stop", result)
	}
}

func TestEvaluateSSHRejectsRemoteHopWhenRegistryIsUnavailable(t *testing.T) {
	result := EvaluateSSH(SSHRequest{Command: "ssh 192.0.2.40 uptime"})
	if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonUnregisteredRemoteHop || !strings.Contains(result.MatchedFragment, "目标清单") {
		t.Fatalf("EvaluateSSH() = %#v, want unavailable-registry remote-hop hard stop", result)
	}
}

func TestEvaluateSQLHardStops(t *testing.T) {
	tests := []struct {
		name     string
		mysql    string
		postgres string
		rule     Reason
	}{
		{name: "opaque effect", mysql: "CALL refresh_users()", postgres: "DO $$ BEGIN NULL; END $$", rule: ReasonOpaqueSQLEffect},
		{name: "drop table", mysql: "DROP TABLE users", postgres: "DROP TABLE users", rule: ReasonDropDatabaseSchemaTable},
		{name: "truncate", mysql: "TRUNCATE TABLE users", postgres: "TRUNCATE TABLE users", rule: ReasonTruncateTable},
		{name: "alter drop", mysql: "ALTER TABLE users DROP COLUMN name", postgres: "ALTER TABLE users DROP COLUMN name", rule: ReasonAlterDrop},
		{name: "unconditional update", mysql: "UPDATE users SET name = 'xiaolong'", postgres: "UPDATE users SET name = 'xiaolong'", rule: ReasonUnconditionalWrite},
		{name: "unconditional delete", mysql: "DELETE FROM users WHERE 1 = 1", postgres: "DELETE FROM users WHERE 1 = 1", rule: ReasonUnconditionalWrite},
	}
	for _, test := range tests {
		for _, dialect := range []struct {
			name      string
			engine    store.DatabaseEngine
			statement string
		}{
			{name: "mysql", engine: store.EngineMySQL, statement: test.mysql},
			{name: "postgres", engine: store.EnginePostgreSQL, statement: test.postgres},
		} {
			t.Run(test.name+"/"+dialect.name, func(t *testing.T) {
				result := EvaluateSQL(SQLRequest{Engine: dialect.engine, Statement: dialect.statement})
				if result.Decision != DecisionPermanentlyRejected || result.Reason != test.rule || result.RuleID != string(test.rule) {
					t.Fatalf("EvaluateSQL(%q) = %#v, want hard stop %q", dialect.statement, result, test.rule)
				}
			})
		}
	}
}

func TestEvaluateSSHDefaultsToDirectForOrdinaryOperations(t *testing.T) {
	for _, request := range []SSHRequest{
		{Command: "sudo systemctl restart mysql"},
		{Command: "rm -rf /data/mysql"},
		{Command: "docker volume rm mysql-data"},
		{Command: "curl -fsS https://example.invalid/health"},
		{Command: "rm -rf /tmp/*"},
		{Command: "if then"}, // Let ordinary syntax errors reach the remote shell.
	} {
		result := EvaluateSSH(request)
		if result.Decision != DecisionAllowed || result.RuleID != "" {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct", request.Command, result)
		}
	}
}

func TestEvaluateSSHAllowsLiteralSedLinePrintCommands(t *testing.T) {
	for _, command := range []string{
		"sed -n '1,120p' /data/code/3proxy-0.9.8/Makefile.Linux",
		"cd /data/code/3proxy-0.9.8 && sed -n '1,120p' Makefile.Linux",
	} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionAllowed || result.Reason != ReasonStaticShell || result.RuleID != "" || result.MatchedFragment != "" {
			t.Fatalf("EvaluateSSH(%q) = %#v, want direct literal shell", command, result)
		}
	}
}

func TestEvaluateSSHRejectsNonReadOnlySedPrograms(t *testing.T) {
	for _, command := range []string{
		"sed 'e id' /tmp/input",
		"sed -i 's/a/b/' /tmp/input",
		"sed -n -e '1,120p' /tmp/input",
		"sed -n '1,120p' -i /tmp/input",
		"sed -n '1,120p' /tmp/*",
		"sed -n '1,120p'",
		"sed -n \"$RANGE\" /tmp/input",
	} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonOpaqueShellEffect || result.RuleID != string(ReasonOpaqueShellEffect) {
			t.Errorf("EvaluateSSH(%q) = %#v, want opaque shell hard stop", command, result)
		}
	}
}

func TestEvaluateSQLDefaultsToDirectForOrdinaryOperations(t *testing.T) {
	tests := []struct {
		engine    store.DatabaseEngine
		statement string
	}{
		{store.EngineMySQL, "SHOW TABLES"},
		{store.EngineMySQL, "SELECT * FROM users LIMIT 100"},
		{store.EngineMySQL, "UPDATE users SET name = 'xiaolong' WHERE id = 6"},
		{store.EngineMySQL, "CREATE TABLE audit_log (id bigint)"},
		{store.EngineMySQL, "SELECT 1; SELECT 2"},
		{store.EngineMySQL, "this is not SQL"},
		{store.EnginePostgreSQL, "SELECT * FROM users LIMIT 100"},
		{store.EnginePostgreSQL, "UPDATE users SET name = 'xiaolong' WHERE id = 6"},
		{store.EnginePostgreSQL, "CREATE TABLE audit_log (id bigint)"},
		{store.EnginePostgreSQL, "SELECT 1; SELECT 2"},
		{store.EnginePostgreSQL, "this is not SQL"},
	}
	for _, test := range tests {
		t.Run(string(test.engine)+"/"+test.statement, func(t *testing.T) {
			result := EvaluateSQL(SQLRequest{Engine: test.engine, Statement: test.statement})
			if result.Decision != DecisionAllowed || result.RuleID != "" {
				t.Fatalf("EvaluateSQL(%q) = %#v, want direct", test.statement, result)
			}
		})
	}
}

func TestInteractiveInputIsCapabilitySignal(t *testing.T) {
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
	for _, command := range []string{
		"sudo systemctl restart mysql",
		"env sudo systemctl restart mysql",
		"sh -c 'sudo systemctl restart mysql'",
	} {
		result := EvaluateSSH(SSHRequest{Command: command})
		if result.Decision != DecisionAllowed || !result.UseNonInteractiveSudo {
			t.Errorf("EvaluateSSH(%q) = %#v, want direct non-interactive sudo signal", command, result)
		}
	}
	if result := EvaluateSSH(SSHRequest{Command: "echo sudo"}); result.UseNonInteractiveSudo {
		t.Fatalf("ordinary sudo argument set UseNonInteractiveSudo: %#v", result)
	}
}

func TestExplicitFiniteLimitsReachTransport(t *testing.T) {
	ssh := EvaluateSSH(SSHRequest{Command: "systemctl restart mysql", Timeout: 3 * time.Minute, MaxBytes: 2 << 20})
	if ssh.Decision != DecisionAllowed || ssh.Timeout != 3*time.Minute || ssh.MaxBytes != 2<<20 {
		t.Fatalf("EvaluateSSH explicit limits = %#v", ssh)
	}
	sql := EvaluateSQL(SQLRequest{Engine: store.EngineMySQL, Statement: "SELECT 1", Timeout: 2 * time.Minute, MaxRows: 5000, MaxBytes: 1 << 20})
	if sql.Decision != DecisionAllowed || sql.Timeout != 2*time.Minute || sql.MaxRows != 5000 || sql.MaxBytes != 1<<20 {
		t.Fatalf("EvaluateSQL explicit limits = %#v", sql)
	}
}

func TestSQLCredentialRouteIsConservativeWithoutBlocking(t *testing.T) {
	tests := []struct {
		engine    store.DatabaseEngine
		statement string
		want      SQLExecutionClass
	}{
		{store.EngineMySQL, "SHOW TABLES", SQLExecutionRead},
		{store.EngineMySQL, "SELECT * FROM users", SQLExecutionRead},
		{store.EngineMySQL, "SELECT * FROM users FOR UPDATE", SQLExecutionMayWrite},
		{store.EngineMySQL, "UPDATE users SET name = 'xiaolong' WHERE id = 6", SQLExecutionMayWrite},
		{store.EnginePostgreSQL, "SELECT * FROM users", SQLExecutionRead},
		{store.EnginePostgreSQL, "SELECT * FROM users FOR UPDATE", SQLExecutionMayWrite},
		{store.EnginePostgreSQL, "UPDATE users SET name = 'xiaolong' WHERE id = 6", SQLExecutionMayWrite},
		{store.EnginePostgreSQL, "not valid SQL", SQLExecutionMayWrite},
	}
	for _, test := range tests {
		result := EvaluateSQL(SQLRequest{Engine: test.engine, Statement: test.statement})
		if result.Decision != DecisionAllowed || result.ExecutionClass != test.want {
			t.Errorf("EvaluateSQL(%q) = %#v, want direct/%q", test.statement, result, test.want)
		}
	}
}

func TestSplitStatementsRemainsDialectAware(t *testing.T) {
	for _, test := range []struct {
		engine    store.DatabaseEngine
		statement string
	}{
		{store.EngineMySQL, "SELECT 'a;b'; SELECT 2"},
		{store.EnginePostgreSQL, "SELECT 'a;b'; SELECT 2"},
	} {
		statements, err := SplitStatements(test.engine, test.statement)
		if err != nil || len(statements) != 2 {
			t.Errorf("SplitStatements(%q) = %#v, %v; want two statements", test.statement, statements, err)
		}
	}
}

func TestPortablePostgreSQLUnconditionalWriteOnlyInspectsWhereClause(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		statement string
		want      bool
	}{
		{statement: "UPDATE users SET enabled = TRUE WHERE id = 1", want: false},
		{statement: "UPDATE users SET enabled = FALSE WHERE enabled = TRUE", want: false},
		{statement: "UPDATE users SET enabled = FALSE WHERE id = 1 RETURNING TRUE", want: false},
		{statement: "DELETE FROM users WHERE TRUE", want: true},
		{statement: "DELETE FROM users WHERE id = 1 OR TRUE", want: true},
		{statement: "DELETE FROM users WHERE id = 1 AND 1 = 1", want: false},
		{statement: "WITH selected AS (SELECT id FROM users) UPDATE users SET enabled = TRUE WHERE id IN (SELECT id FROM selected)", want: false},
	} {
		_, got := portablePostgreSQLHardStop(test.statement)
		if got != test.want {
			t.Fatalf("portablePostgreSQLHardStop(%q) = %t, want %t", test.statement, got, test.want)
		}
	}
}

func TestPortablePostgreSQLBackslashInOrdinaryStringDoesNotHideStatement(t *testing.T) {
	statement := "SELECT 'foo\\'; DELETE FROM users"
	result := EvaluateSQL(SQLRequest{Engine: store.EnginePostgreSQL, Statement: statement})
	if result.Decision != DecisionPermanentlyRejected || result.Reason != ReasonUnconditionalWrite {
		t.Fatalf("EvaluateSQL(%q) = %#v, want unconditional-write hard stop", statement, result)
	}
}

func TestPortablePostgreSQLEscapeStringKeepsEmbeddedSemicolon(t *testing.T) {
	statement := "SELECT E'foo\\\\'; SELECT 2"
	statements := splitPortablePostgreSQL(statement)
	if len(statements) != 2 {
		t.Fatalf("splitPortablePostgreSQL(%q) = %#v, want two statements", statement, statements)
	}
}

func TestHardStopFragmentsAreUserFacingChineseOrSQL(t *testing.T) {
	result := EvaluateSSH(SSHRequest{Command: "mkfs.ext4 /dev/sdb"})
	if result.MatchedFragment == "" || strings.Contains(result.MatchedFragment, "formatting") {
		t.Fatalf("MatchedFragment = %q, want short user-facing text", result.MatchedFragment)
	}
}
