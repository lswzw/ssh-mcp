package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/runner"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

func TestNewServerCreatesMCPServer(t *testing.T) {
	server := NewServer("test-version")
	if server == nil {
		t.Fatal("NewServer() returned nil")
	}
}

func TestServeInitializationDoesNotStartDaemon(t *testing.T) {
	t.Parallel()

	starts := 0
	server := newServeServer("test-version", RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		starts++
		return nil, errors.New("daemon must not start during MCP initialization")
	})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()
	if starts != 0 {
		t.Fatalf("daemon starts during MCP initialization = %d, want 0", starts)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestNewServerPublishesRemoteUseInstructions(t *testing.T) {
	t.Parallel()

	server := NewServer("test-version", runner.New(runner.Dependencies{}))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	instructions := session.InitializeResult().Instructions
	for _, required := range []string{"ssh-mcp", "MCP", "本地 shell", "登记目标", "describe_target_capability", "固定硬拦截", "命令黑名单", "target_command_blacklist", "当前用户请求任务链", "同一效果", "本地 TUI", "outcome_unknown", "不自动重试", "rule_id", "matched_fragment", "handoff_command", "MCP 外", "arguments 必须是单一、合法、完整的 JSON 对象字符串", "input schema", "代码围栏", `{"target":"192.0.2.10","command":"ls /data"}`} {
		if !strings.Contains(instructions, required) {
			t.Fatalf("instructions = %q, missing %q", instructions, required)
		}
	}
	for _, forbidden := range []string{"维护会话", "人工授权", "授权时长", "命令确认", "operation_id", "start_maintenance_session", "approve_operation", "create_review_plan", "submit_review_receipt", "execute_reviewed_plan", "autonomous", "严格模式", "应根据中文原因改写命令"} {
		if strings.Contains(instructions, forbidden) {
			t.Fatalf("instructions = %q，意外包含旧术语 %q", instructions, forbidden)
		}
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestToolDescriptionsIncludeCallArgumentExamples(t *testing.T) {
	t.Parallel()

	server := NewServer("test-version", runner.New(runner.Dependencies{}))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(listed.Tools) == 0 {
		t.Fatal("ListTools() returned no tools")
	}
	for _, tool := range listed.Tools {
		if !strings.Contains(tool.Description, "Example call arguments") && !strings.Contains(tool.Description, "调用示例 arguments") {
			t.Fatalf("tool %q description lacks a call argument example: %q", tool.Name, tool.Description)
		}
	}
	var deploymentDescription string
	for _, tool := range listed.Tools {
		if tool.Name == "deploy_ssh_binary" {
			deploymentDescription = tool.Description
		}
	}
	for _, required := range []string{"source_path", "remote_path", "start_action", "temporary file", "backup"} {
		if !strings.Contains(deploymentDescription, required) {
			t.Fatalf("deployment tool description = %q, missing %q", deploymentDescription, required)
		}
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPDeploySSHBinaryRoutesDirectPathsAndBoundedBudgets(t *testing.T) {
	t.Parallel()

	daemon := &fakeDaemonToolExecutor{deployResult: runner.Result{Status: runner.StatusCompleted}}
	server := newServeServer("test-version", RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		return daemon, nil
	})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "deploy_ssh_binary", Arguments: map[string]any{
		"target": "192.0.2.10", "source_path": "/tmp/release", "remote_path": "/srv/app/release", "start_action": "systemctl restart app",
		"max_bytes": float64(123456), "timeout_seconds": float64(321),
	}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("CallTool(deploy_ssh_binary) result = %#v, error = %v", result, err)
	}
	if daemon.deployCalls != 1 || daemon.deployRequest.Target != "192.0.2.10" || daemon.deployRequest.SourcePath != "/tmp/release" || daemon.deployRequest.RemotePath != "/srv/app/release" || daemon.deployRequest.StartAction != "systemctl restart app" || daemon.deployRequest.MaxBytes != 123456 || daemon.deployRequest.Timeout != 321*time.Second {
		t.Fatalf("deployment request = %#v, calls = %d", daemon.deployRequest, daemon.deployCalls)
	}
	if got := mcpResultStatus(t, result); got != runner.StatusCompleted {
		t.Fatalf("deployment status = %q", got)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestSecondsDurationSaturatesInsteadOfOverflowing(t *testing.T) {
	t.Parallel()

	if got := secondsDuration(int(^uint(0) >> 1)); got <= 0 {
		t.Fatalf("secondsDuration(max int) = %v, want a positive saturated duration", got)
	}
	if got := secondsDuration(-1); got >= 0 {
		t.Fatalf("secondsDuration(-1) = %v, want a negative duration for runner rejection", got)
	}
}

func TestMCPDeploySSHBinarySaturatesTimeoutSecondsOverflow(t *testing.T) {
	t.Parallel()

	const maxDuration = time.Duration(1<<63 - 1)
	overflowSeconds := int(maxDuration/time.Second) + 1
	daemon := &fakeDaemonToolExecutor{deployResult: runner.Result{Status: runner.StatusCompleted}}
	server := newServeServer("test-version", RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		return daemon, nil
	})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "deploy_ssh_binary", Arguments: map[string]any{
		"target": "192.0.2.10", "source_path": "/tmp/release", "remote_path": "/srv/app/release",
		"timeout_seconds": float64(overflowSeconds),
	}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("CallTool(deploy_ssh_binary) result = %#v, error = %v", result, err)
	}
	if daemon.deployCalls != 1 || daemon.deployRequest.Timeout != maxDuration {
		t.Fatalf("deployment timeout = %v, calls = %d, want saturated %v", daemon.deployRequest.Timeout, daemon.deployCalls, maxDuration)
	}

	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestRemoteResultDoesNotHideStructuredToolOutput(t *testing.T) {
	if result := remoteResult(runner.Result{UntrustedRemoteOutput: true}); result != nil {
		t.Fatalf("remoteResult() = %#v, want nil so the SDK emits the typed result as text and structured content", result)
	}
}

func TestRuntimeServerRegistersOnlyTheScopedRemoteTools(t *testing.T) {
	t.Parallel()

	server := NewServer("test-version", runner.New(runner.Dependencies{}))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"close_ssh_session", "deploy_ssh_binary", "describe_target_capability", "execute_ssh_session", "list_databases", "list_targets", "open_ssh_session", "read_ssh_file", "run_sql", "run_ssh", "set_ssh_session_context"}) {
		t.Fatalf("tools = %#v", names)
	}
	for _, name := range []string{"start_maintenance_session", "approve_operation", "create_review_plan", "submit_review_receipt", "execute_reviewed_plan"} {
		result, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
		if callErr == nil && (result == nil || !result.IsError) {
			t.Fatalf("CallTool(%q) 意外成功：%#v", name, result)
		}
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPDescribesCapabilityWithoutOpeningVaultOrRemoteConnection(t *testing.T) {
	t.Parallel()

	server := NewServer("test-version", runner.New(runner.Dependencies{Targets: mcpTestTargets{}}))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "describe_target_capability", Arguments: map[string]any{
		"target": "192.0.2.10", "protocol": "ssh",
	}})
	if err != nil || result.IsError {
		t.Fatalf("CallTool(describe_target_capability) result = %#v, error = %v", result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured capability: %v", err)
	}
	var capability struct {
		Target              string `json:"target"`
		Protocol            string `json:"protocol"`
		PolicyVersion       string `json:"policy_version"`
		DefaultOutputBytes  int    `json:"default_output_bytes"`
		MaxOperationSeconds int    `json:"max_operation_seconds"`
	}
	if err := json.Unmarshal(encoded, &capability); err != nil {
		t.Fatalf("unmarshal capability: %v", err)
	}
	if capability.Target != "192.0.2.10" || capability.Protocol != "ssh" || capability.PolicyVersion == "" || capability.DefaultOutputBytes != 16<<10 || capability.MaxOperationSeconds != 0 {
		t.Fatalf("capability = %#v", capability)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPRunSSHReturnsOriginalUntrustedResultWithoutPersistingOutput(t *testing.T) {
	t.Parallel()

	audit := &mcpTestAudit{}
	engine := runner.New(runner.Dependencies{
		Targets:   mcpTestTargets{},
		Sessions:  mcpTestSessions{},
		SSH:       mcpTestSSH{result: sshtransport.ExecutionResult{Stdout: "password=do-not-return", ExitStatus: 0}},
		Audit:     audit,
		OpenTUI:   func() error { return nil },
		SessionID: "mcp-e2e-test",
	})
	server := NewServer("test-version", engine)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "run_ssh", Arguments: map[string]any{
		"target": "192.0.2.10", "command": "free -m",
	}})
	if err != nil {
		t.Fatalf("CallTool(run_ssh) error = %v", err)
	}
	if result.IsError || len(result.Content) != 1 {
		t.Fatalf("CallTool(run_ssh) result = %#v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, `"untrusted_remote_output":true`) || !strings.Contains(text.Text, "do-not-return") {
		t.Fatalf("CallTool(run_ssh) text = %#v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured result: %v", err)
	}
	var output struct {
		Status                string `json:"status"`
		UntrustedRemoteOutput bool   `json:"untrusted_remote_output"`
		SSH                   struct {
			Stdout string `json:"stdout"`
		} `json:"ssh"`
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("unmarshal structured result: %v", err)
	}
	if output.Status != runner.StatusCompleted || !output.UntrustedRemoteOutput || output.SSH.Stdout != "password=do-not-return" {
		t.Fatalf("structured output = %#v", output)
	}
	if len(audit.entries) != 2 || audit.entries[1].SSHCommand != "free -m" {
		t.Fatalf("audit entries = %#v", audit.entries)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPExecutesStaticSSHWithoutRemovedReviewWorkflow(t *testing.T) {
	t.Parallel()

	audit := &mcpTestAudit{}
	engine := runner.New(runner.Dependencies{
		Targets:   mcpTestTargets{},
		Sessions:  mcpTestSessions{},
		SSH:       mcpTestSSH{result: sshtransport.ExecutionResult{Stdout: "must not be returned", ExitStatus: 0}},
		Audit:     audit,
		OpenTUI:   func() error { return nil },
		SessionID: "mcp-static-ssh-test",
	})
	server := NewServer("test-version", engine)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "run_ssh", Arguments: map[string]any{
		"target": "192.0.2.10", "command": "printf ready > /tmp/mcp-review.log",
	}})
	if err != nil || result.IsError || mcpResultStatus(t, result) != runner.StatusCompleted {
		t.Fatalf("CallTool(run_ssh static command) result = %#v, error = %v", result, err)
	}
	if len(audit.entries) != 2 || !audit.entries[1].RemoteExecuted || audit.entries[1].Result.Status != runner.StatusCompleted {
		t.Fatalf("static command audit = %#v", audit.entries)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPRejectsFixedSSHHardStopWithoutRemoteDispatch(t *testing.T) {
	t.Parallel()

	audit := &mcpTestAudit{}
	ssh := &countingMCPTestSSH{result: sshtransport.ExecutionResult{ExitStatus: 0}}
	server := NewServer("test-version", runner.New(runner.Dependencies{
		Targets:   mcpTestTargets{},
		Sessions:  mcpTestSessions{},
		SSH:       ssh,
		Audit:     audit,
		OpenTUI:   func() error { return nil },
		SessionID: "mcp-prohibition-test",
	}))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "run_ssh", Arguments: map[string]any{
		"target": "192.0.2.10", "command": "mkfs.ext4 /dev/sdb",
	}})
	if err != nil || result.IsError || mcpResultStatus(t, result) != runner.StatusRejected {
		t.Fatalf("CallTool(run_ssh prohibited) result = %#v, error = %v", result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured hard-stop result: %v", err)
	}
	var output struct {
		RuleID          string `json:"rule_id"`
		MatchedFragment string `json:"matched_fragment"`
		HandoffCommand  string `json:"handoff_command"`
		Message         string `json:"message"`
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("unmarshal structured hard-stop result: %v", err)
	}
	if output.RuleID == "" || output.MatchedFragment == "" || output.HandoffCommand == "" ||
		!strings.Contains(output.Message, "操作未派发") || !strings.Contains(output.Message, "人工") || !strings.Contains(output.Message, "MCP 外") {
		t.Fatalf("hard-stop result does not carry human handoff details: %#v", output)
	}
	if len(audit.entries) != 1 || audit.entries[0].RemoteExecuted || audit.entries[0].Result.Status != runner.StatusRejected || ssh.calls != 0 {
		t.Fatalf("prohibited audit = %#v, SSH calls = %d", audit.entries, ssh.calls)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func TestMCPUsesExplicitStructuredSSHWorkSession(t *testing.T) {
	t.Parallel()

	engine := runner.New(runner.Dependencies{
		Targets:   mcpTestTargets{},
		Sessions:  mcpTestSessions{},
		SSH:       mcpTestSSH{result: sshtransport.ExecutionResult{ExitStatus: 0}},
		Audit:     &mcpTestAudit{},
		OpenTUI:   func() error { return nil },
		SessionID: "mcp-work-session-test",
	})
	server := NewServer("test-version", engine)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	opened, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "open_ssh_session", Arguments: map[string]any{"target": "192.0.2.10"}})
	if err != nil || opened.IsError {
		t.Fatalf("CallTool(open_ssh_session) = %#v, %v", opened, err)
	}
	sessionID := mcpWorkSessionID(t, opened)
	updated, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "set_ssh_session_context", Arguments: map[string]any{
		"session_id": sessionID, "working_directory": "/srv/app", "environment": map[string]string{"APP_ENV": "production"},
	}})
	if err != nil || updated.IsError || mcpResultStatus(t, updated) != runner.StatusSSHSessionContextUpdated {
		t.Fatalf("CallTool(set_ssh_session_context) = %#v, %v", updated, err)
	}
	executed, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "execute_ssh_session", Arguments: map[string]any{
		"session_id": sessionID, "command": "free -m",
	}})
	if err != nil || executed.IsError || mcpResultStatus(t, executed) != runner.StatusCompleted {
		t.Fatalf("CallTool(execute_ssh_session) = %#v, %v", executed, err)
	}
	closed, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "close_ssh_session", Arguments: map[string]any{"session_id": sessionID}})
	if err != nil || closed.IsError || mcpResultStatus(t, closed) != runner.StatusSSHSessionClosed {
		t.Fatalf("CallTool(close_ssh_session) = %#v, %v", closed, err)
	}
	cancel()
	if err := <-serverDone; err != nil && err != context.Canceled {
		t.Fatalf("server.Run() error = %v", err)
	}
}

func mcpResultStatus(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured result: %v", err)
	}
	var output struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("unmarshal structured result: %v", err)
	}
	return output.Status
}

func mcpWorkSessionID(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal SSH session result: %v", err)
	}
	var output struct {
		Status  string `json:"status"`
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("unmarshal SSH session result: %v", err)
	}
	if output.Status != runner.StatusSSHSessionOpened || output.Session.ID == "" {
		t.Fatalf("SSH session output = %#v", output)
	}
	return output.Session.ID
}

type mcpTestTargets struct{}

func (mcpTestTargets) ListSSHTargets(context.Context) ([]store.SSHTarget, error) { return nil, nil }
func (mcpTestTargets) ListDatabaseInstances(context.Context) ([]store.DatabaseInstance, error) {
	return nil, nil
}
func (mcpTestTargets) SSHTarget(context.Context, string) (store.SSHTarget, error) {
	return store.SSHTarget{IP: "192.0.2.10", SSHPort: 22, LoginUsername: "ops", Enabled: true, IdentityStatus: store.SSHIdentityVerified}, nil
}
func (mcpTestTargets) DatabaseInstance(_ context.Context, host string, port int) (store.DatabaseInstance, error) {
	if host == "192.0.2.20" && port == 5432 {
		return store.DatabaseInstance{Host: host, Port: port, Engine: store.EnginePostgreSQL, DefaultDatabase: "app", ReadUsername: "app_read", ReadCredentialID: "read", WriteUsername: "app_write", WriteCredentialID: "write", Enabled: true, MajorVersion: 16, VersionStatus: store.DatabaseVersionVerified}, nil
	}
	return store.DatabaseInstance{}, store.ErrTargetNotFound
}

type mcpTestSessions struct{}

func (mcpTestSessions) Vault() (*store.Vault, error) { return &store.Vault{}, nil }
func (mcpTestSessions) TouchRemoteActivity()         {}

type mcpTestSSH struct{ result sshtransport.ExecutionResult }

func (s mcpTestSSH) Execute(context.Context, *store.Vault, store.SSHTarget, string, bool, int) (sshtransport.ExecutionResult, error) {
	return s.result, nil
}

func (s mcpTestSSH) ExecuteIsolated(context.Context, *store.Vault, store.SSHTarget, string, string, bool, int) (sshtransport.ExecutionResult, error) {
	return s.result, nil
}

type countingMCPTestSSH struct {
	result sshtransport.ExecutionResult
	calls  int
}

func (s *countingMCPTestSSH) Execute(context.Context, *store.Vault, store.SSHTarget, string, bool, int) (sshtransport.ExecutionResult, error) {
	s.calls++
	return s.result, nil
}

func (s *countingMCPTestSSH) ExecuteIsolated(context.Context, *store.Vault, store.SSHTarget, string, string, bool, int) (sshtransport.ExecutionResult, error) {
	s.calls++
	return s.result, nil
}

type mcpTestAudit struct{ entries []auditlog.Event }

func (a *mcpTestAudit) Record(_ context.Context, entry auditlog.Event) error {
	a.entries = append(a.entries, entry)
	return nil
}
