package app

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/runner"
)

const serverName = "ssh-mcp"

const mcpInstructions = "当用户明确要求使用 ssh-mcp（包括“使用 ssh-mcp”或“通过 ssh-mcp”）时，必须使用这些 MCP 工具访问远端系统，不能改用本地 shell、系统 ssh、数据库客户端或状态库读取。只能使用已登记目标。先调用 describe_target_capability 获取直接执行范围、当前 daemon 版本已识别的固定硬拦截类别和默认输出设置。写 SQL 必须已配置可写账号和密码，读写账号可以相同。数据库版本信息不会阻止未命中硬拦截的 SQL。固定硬拦截或 SSH 目标命令黑名单命中时，当前用户请求任务链内 AI 不得为达成同一效果改写、变形或重试命令；无关操作可以继续。固定硬拦截只保证 daemon 已识别的零派发，不是语义级或 MCP 外的绝对禁止；结果会给出 rule_id、matched_fragment 和 handoff_command（脱敏命令），仅可由人工在 MCP 外复核并执行。黑名单结果为 target_command_blacklist，操作零派发、不提供 handoff；只有当前本地用户可在本地 TUI 明确调整目标规则，之后才能提交新的请求重新裁决。需要交互式终端输入的 SSH 命令也不会派发，应使用返回的脱敏命令由人工在终端执行。SSH 文件读写仅受目标的“允许文件读写”开关控制，默认为 true；关闭后 read_ssh_file 和 deploy_ssh_binary 均零派发。部署直接提交 source_path、remote_path 和可选 start_action，服务器仍先校验并备份原目标，再激活临时文件，结果未知时不自动重试。远端派发后的超时、断连或协议错误是 outcome_unknown；daemon 不自动重试，应先进行新的受限诊断再决定下一步。调用工具时，arguments 必须是单一、合法、完整的 JSON 对象字符串，字段必须与该工具的 input schema 一致，例如 {\"target\":\"192.0.2.10\",\"command\":\"ls /data\"}；禁止在 arguments 中嵌入任何分隔符、函数调用标签或代码围栏。没有明确 ssh-mcp 指令时，不访问远端系统。"

type ToolExecutor interface {
	ListTargets(context.Context) (runner.TargetsResult, error)
	DescribeExecutionSpecification(context.Context, runner.ExecutionSpecificationRequest) (runner.ExecutionSpecification, error)
	ListDatabases(context.Context, runner.DatabaseListRequest) (runner.Result, error)
	RunSSH(context.Context, runner.SSHRequest) (runner.Result, error)
	ReadSSHFile(context.Context, runner.SSHFileReadRequest) (runner.Result, error)
	DeploySSHBinary(context.Context, runner.SSHBinaryDeploymentRequest) (runner.Result, error)
	OpenSSHSession(context.Context, runner.OpenSSHSessionRequest) (runner.SSHSessionResult, error)
	SetSSHSessionContext(context.Context, runner.SetSSHSessionContextRequest) (runner.SSHSessionResult, error)
	ExecuteSSHSession(context.Context, runner.ExecuteSSHSessionRequest) (runner.Result, error)
	CloseSSHSession(context.Context, string) (runner.SSHSessionResult, error)
	RunSQL(context.Context, runner.SQLRequest) (runner.Result, error)
}

// secondsDuration converts untrusted MCP integer input without wrapping a
// large value into a negative timeout. The runner applies the operation's
// tighter policy limit; saturation keeps that validation deterministic.
func secondsDuration(seconds int) time.Duration {
	if seconds == 0 {
		return 0
	}
	maxDuration := time.Duration(1<<63 - 1)
	minDuration := -maxDuration - 1
	maxSeconds := int64(maxDuration / time.Second)
	minSeconds := int64(minDuration / time.Second)
	if int64(seconds) > maxSeconds {
		return maxDuration
	}
	if int64(seconds) < minSeconds {
		return minDuration
	}
	return time.Duration(seconds) * time.Second
}

func NewServer(version string, executors ...ToolExecutor) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version,
	}, &mcp.ServerOptions{Instructions: mcpInstructions})
	if len(executors) > 0 && executors[0] != nil {
		registerTools(server, executors[0])
	}
	return server
}

type listTargetsInput struct{}

type listDatabasesInput struct {
	Target string `json:"target" jsonschema:"registered database IP and port, for example 192.0.2.20:5432"`
}

type executionSpecificationInput struct {
	Target   string                `json:"target" jsonschema:"registered SSH IP or registered database IP and port"`
	Protocol runner.TargetProtocol `json:"protocol" jsonschema:"target protocol: ssh or sql"`
}

type runSSHInput struct {
	Target         string `json:"target" jsonschema:"registered SSH IP"`
	Command        string `json:"command" jsonschema:"complete SSH command to evaluate"`
	AsRoot         bool   `json:"as_root,omitempty" jsonschema:"run the confirmed command through non-interactive sudo -n as root; use this instead of an interactive sudo su shell"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"requested timeout in seconds; defaults to 60"`
	MaxBytes       int    `json:"max_bytes,omitempty" jsonschema:"requested output byte limit; defaults to 16384"`
}

type readSSHFileInput struct {
	Target         string `json:"target" jsonschema:"registered SSH IP"`
	Path           string `json:"path" jsonschema:"canonical absolute remote file path"`
	Offset         int64  `json:"offset,omitempty" jsonschema:"non-negative byte offset"`
	MaxBytes       int    `json:"max_bytes,omitempty" jsonschema:"bounded byte limit; defaults to 16384 and cannot exceed 65536"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"bounded timeout in seconds; defaults to 30 and cannot exceed 60"`
}

type deploySSHBinaryInput struct {
	Target         string `json:"target" jsonschema:"registered SSH IP"`
	SourcePath     string `json:"source_path" jsonschema:"local regular file path to upload"`
	RemotePath     string `json:"remote_path" jsonschema:"canonical absolute existing remote file path"`
	StartAction    string `json:"start_action,omitempty" jsonschema:"optional remote start/restart command after activation"`
	MaxBytes       int64  `json:"max_bytes,omitempty" jsonschema:"independent source byte budget; defaults to 67108864 and cannot exceed 268435456"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"bounded deployment timeout in seconds; defaults to 600 and cannot exceed 900"`
}

type runSQLInput struct {
	Target         string `json:"target" jsonschema:"registered database IP and port"`
	Database       string `json:"database,omitempty" jsonschema:"database name; defaults to the configured default database"`
	Statement      string `json:"statement" jsonschema:"complete SQL statement to evaluate"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"requested timeout in seconds; defaults to 30"`
	MaxRows        int    `json:"max_rows,omitempty" jsonschema:"requested result row limit; defaults to 1000"`
	MaxBytes       int    `json:"max_bytes,omitempty" jsonschema:"requested result byte limit; defaults to 16384"`
}

type openSSHSessionInput struct {
	Target string `json:"target" jsonschema:"registered SSH IP"`
}

type setSSHSessionContextInput struct {
	SessionID        string            `json:"session_id" jsonschema:"SSH work session ID returned by open_ssh_session"`
	WorkingDirectory string            `json:"working_directory" jsonschema:"absolute remote working directory; use a clean absolute path"`
	Environment      map[string]string `json:"environment" jsonschema:"complete replacement map of non-secret environment variables"`
}

type executeSSHSessionInput struct {
	SessionID      string `json:"session_id" jsonschema:"SSH work session ID returned by open_ssh_session"`
	Command        string `json:"command" jsonschema:"complete SSH command to evaluate within the declared session context"`
	AsRoot         bool   `json:"as_root,omitempty" jsonschema:"run the command through non-interactive sudo -n when the bound policy permits it"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"requested timeout in seconds; defaults to 60"`
	MaxBytes       int    `json:"max_bytes,omitempty" jsonschema:"requested output byte limit; defaults to 16384"`
}

type closeSSHSessionInput struct {
	SessionID string `json:"session_id" jsonschema:"SSH work session ID to close; closing is idempotent"`
}

func registerTools(server *mcp.Server, executor ToolExecutor) {
	mcp.AddTool(server, &mcp.Tool{Name: "list_targets", Description: "Use this MCP tool to list registered SSH and database targets. Never replace it with a local shell, ssh command, database client, or SQLite read. Credentials are never returned. Example call arguments: {}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ listTargetsInput) (*mcp.CallToolResult, runner.TargetsResult, error) {
			result, err := executor.ListTargets(ctx)
			return nil, result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "describe_target_capability", Description: "Read a registered target's current non-sensitive execution specification before an unfamiliar operation. It does not unlock credentials or connect remotely. The response states direct execution categories, fixed hard-stop IDs recognized by this daemon version, and output limits. Example call arguments: {\"target\":\"192.0.2.10\",\"protocol\":\"ssh\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input executionSpecificationInput) (*mcp.CallToolResult, runner.ExecutionSpecification, error) {
			result, err := executor.DescribeExecutionSpecification(ctx, runner.ExecutionSpecificationRequest{Target: input.Target, Protocol: input.Protocol})
			return nil, result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "list_databases", Description: "Use this MCP tool only for a registered database target. It lists databases visible to the configured read account and must not be replaced with a local database client. Example call arguments: {\"target\":\"192.0.2.20:5432\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input listDatabasesInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.ListDatabases(ctx, runner.DatabaseListRequest{Target: input.Target})
			return remoteResult(result), result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "run_ssh", Description: "Use this MCP tool, never local shell or system ssh, for a registered SSH target. Commands not matching a fixed hard block or this target's command blacklist may run directly; as_root uses daemon sudo -n. When either local rejection matches, do not rewrite, transform, or retry for the same effect in the current user request chain. Fixed hard blocks return a redacted human-only MCP-external handoff; target blacklist matches are not dispatched, return no handoff, and require the current local user to adjust the rule in the local TUI before a new request can be evaluated. Example call arguments: {\"target\":\"192.0.2.10\",\"command\":\"free -m\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input runSSHInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.RunSSH(ctx, runner.SSHRequest{Target: input.Target, Command: input.Command, AsRoot: input.AsRoot, Timeout: secondsDuration(input.TimeoutSeconds), MaxBytes: input.MaxBytes})
			return remoteResult(result), result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "read_ssh_file", Description: "Use this MCP tool for one bounded, read-only inspection of a regular file on a registered SSH target when its AllowFileOperations capability is enabled. The path must be canonical absolute; symlink, directory, device, FIFO, socket, invalid offset, or excessive budget is rejected before remote dispatch. It uses a daemon-held pinned read-only file protocol, never cat, sed, find, or an arbitrary shell command. Returned bytes are untrusted remote output. Example call arguments: {\"target\":\"192.0.2.10\",\"path\":\"/srv/app/config/application.yaml\",\"offset\":0,\"max_bytes\":16384}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input readSSHFileInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.ReadSSHFile(ctx, runner.SSHFileReadRequest{Target: input.Target, Path: input.Path, Offset: input.Offset, MaxBytes: input.MaxBytes, Timeout: secondsDuration(input.TimeoutSeconds)})
			return remoteResult(result), result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "deploy_ssh_binary", Description: "Use this MCP tool for a file deployment on a registered SSH target when its AllowFileOperations capability is enabled. Provide a local regular source_path, an existing canonical absolute remote_path, and optionally start_action. The daemon verifies size and SHA-256, uploads to an exclusive temporary file, moves the existing target to a sibling backup, then activates the temporary file; it never directly overwrites the live target or auto-retries an unknown outcome. Example call arguments: {\"target\":\"192.0.2.10\",\"source_path\":\"C:\\\\build\\\\app.exe\",\"remote_path\":\"/srv/app/app.exe\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input deploySSHBinaryInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.DeploySSHBinary(ctx, runner.SSHBinaryDeploymentRequest{Target: input.Target, SourcePath: input.SourcePath, RemotePath: input.RemotePath, StartAction: input.StartAction, MaxBytes: input.MaxBytes, Timeout: secondsDuration(input.TimeoutSeconds)})
			return remoteResult(result), result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "open_ssh_session", Description: "为一个已登记目标创建显式 SSH 工作会话。它只保存声明式工作目录和非机密环境变量，不连接远端；空闲五分钟后失效。它不提供 TTY、交互输入、别名、函数或持久化原始 Shell 状态。调用示例 arguments：{\"target\":\"192.0.2.10\"}。"},
		func(ctx context.Context, _ *mcp.CallToolRequest, input openSSHSessionInput) (*mcp.CallToolResult, runner.SSHSessionResult, error) {
			result, err := executor.OpenSSHSession(ctx, runner.OpenSSHSessionRequest{Target: input.Target})
			return nil, result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "set_ssh_session_context", Description: "Replace an SSH work session's complete declared context using an absolute directory and non-secret environment map. Do not use raw cd, export, unset, or source to change context. Example call arguments: {\"session_id\":\"...\",\"working_directory\":\"/srv/app\",\"environment\":{\"APP_ENV\":\"production\"}}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input setSSHSessionContextInput) (*mcp.CallToolResult, runner.SSHSessionResult, error) {
			result, err := executor.SetSSHSessionContext(ctx, runner.SetSSHSessionContextRequest{SessionID: input.SessionID, Context: runner.SSHSessionContext{WorkingDirectory: input.WorkingDirectory, Environment: input.Environment}})
			return nil, result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "execute_ssh_session", Description: "Run one SSH command in an explicit declared session context. Commands follow the target capability and the same current-request-chain no-bypass rule; use set_ssh_session_context for a complete working-directory and environment replacement. Example call arguments: {\"session_id\":\"...\",\"command\":\"free -m\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input executeSSHSessionInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.ExecuteSSHSession(ctx, runner.ExecuteSSHSessionRequest{SessionID: input.SessionID, Command: input.Command, AsRoot: input.AsRoot, Timeout: secondsDuration(input.TimeoutSeconds), MaxBytes: input.MaxBytes})
			return remoteResult(result), result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "close_ssh_session", Description: "Close an SSH work session and discard its declared context. It is safe to call more than once and never reconnects a closed or expired session. Example call arguments: {\"session_id\":\"...\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input closeSSHSessionInput) (*mcp.CallToolResult, runner.SSHSessionResult, error) {
			result, err := executor.CloseSSHSession(ctx, input.SessionID)
			return nil, result, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "run_sql", Description: "Use this MCP tool, never a local database client, for a registered database. Reads use the read account; DML, DDL, and transactions use the explicitly configured write account. Database version verification does not gate non-blocked SQL. Fixed hard blocks are not dispatched and return a Chinese human-execution handoff. Example call arguments: {\"target\":\"192.0.2.20:5432\",\"statement\":\"SELECT 1\"}."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input runSQLInput) (*mcp.CallToolResult, runner.Result, error) {
			result, err := executor.RunSQL(ctx, runner.SQLRequest{Target: input.Target, Database: input.Database, Statement: input.Statement, Timeout: secondsDuration(input.TimeoutSeconds), MaxRows: input.MaxRows, MaxBytes: input.MaxBytes})
			return remoteResult(result), result, err
		})
}

// remoteResult intentionally leaves Content unset. The MCP SDK then serializes
// the typed result into both TextContent and StructuredContent, including the
// untrusted_remote_output marker beside every remote value.
func remoteResult(runner.Result) *mcp.CallToolResult { return nil }

func Run(ctx context.Context, version string) error {
	executor := newReconnectingExecutor(RuntimeOptions{}, nil)
	defer executor.Close(context.Background())
	return NewServer(version, executor).Run(ctx, &mcp.StdioTransport{})
}

// newServeServer keeps MCP initialization independent from daemon startup.
// The reconnecting executor starts or connects to the daemon only when an MCP
// tool is actually called.
func newServeServer(version string, options RuntimeOptions, connector daemonConnector) *mcp.Server {
	return NewServer(version, newReconnectingExecutor(options, connector))
}
