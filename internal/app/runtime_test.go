package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/control"
	"ssh-mcp/internal/instance"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/paths"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/runner"
	"ssh-mcp/internal/sshservice"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
	"ssh-mcp/internal/terminal"
)

func TestRuntimeServesAuthenticatedLocalControlAndCleansUp(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	var status control.Status
	err = ipc.NewClient(runtime.SocketPath(), runtime.Token()).Call(context.Background(), "status", nil, &status)
	if err != nil {
		t.Fatalf("status IPC call error = %v", err)
	}
	if status.Initialized || status.Unlocked {
		t.Fatalf("initial runtime status = %#v", status)
	}
	if err := ipc.NewClient(runtime.SocketPath(), runtime.Token()).Call(context.Background(), "tui.connected", nil, &struct{}{}); err != nil {
		t.Fatalf("tui connected IPC call error = %v", err)
	}
	if !runtime.hasActiveTUI(time.Now()) {
		t.Fatal("runtime did not retain active TUI state")
	}
	if err := ipc.NewClient(runtime.SocketPath(), runtime.Token()).Call(context.Background(), "tui.disconnected", nil, &struct{}{}); err != nil {
		t.Fatalf("tui disconnected IPC call error = %v", err)
	}
	if runtime.hasActiveTUI(time.Now()) {
		t.Fatal("runtime retained disconnected TUI state")
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertControlEndpointClosed(t, runtime.SocketPath(), runtime.Token())
}

func TestRuntimeRejectsUnauthenticatedControlCalls(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	for _, token := range []string{"", "wrong-control-token"} {
		assertUnauthenticatedControl(t, runtime, token)
	}
}

func TestRuntimeRotatesControlTokenForEachTUILaunch(t *testing.T) {
	t.Parallel()

	runtime := newStartedRuntime(t, RuntimeOptions{})
	initialToken := runtime.Token()
	first, alreadyOpen, err := runtime.beginTUILaunch()
	if err != nil {
		t.Fatalf("beginTUILaunch() error = %v", err)
	}
	if alreadyOpen {
		t.Fatal("first beginTUILaunch() reported an active TUI")
	}
	if first.token == "" || first.token == initialToken {
		t.Fatalf("first launch token = %q, initial token = %q", first.token, initialToken)
	}
	assertUnauthenticatedControl(t, runtime, initialToken)
	assertControlTokenAccepted(t, runtime, first.token)

	runtime.expireUnconnectedTUILaunch(first.token)
	assertUnauthenticatedControl(t, runtime, first.token)
	if got := runtime.Token(); got != "" {
		t.Fatalf("expired launch token = %q, want empty", got)
	}

	second, alreadyOpen, err := runtime.beginTUILaunch()
	if err != nil {
		t.Fatalf("second beginTUILaunch() error = %v", err)
	}
	if alreadyOpen {
		t.Fatal("second beginTUILaunch() reported an active TUI")
	}
	if second.token == "" || second.token == first.token || second.token == initialToken {
		t.Fatalf("second launch token = %q, first = %q, initial = %q", second.token, first.token, initialToken)
	}
	assertControlTokenAccepted(t, runtime, second.token)
}

func TestRuntimeInvalidatesControlTokenWhenTUIStartFails(t *testing.T) {
	t.Parallel()

	runtime := newStartedRuntime(t, RuntimeOptions{TerminalSpec: "unsupported-terminal"})
	previousToken := runtime.Token()
	if err := runtime.OpenTUI(); !errors.Is(err, terminal.ErrInvalidConfiguration) {
		t.Fatalf("OpenTUI() error = %v, want ErrInvalidConfiguration", err)
	}
	assertUnauthenticatedControl(t, runtime, previousToken)
	if got := runtime.Token(); got != "" {
		t.Fatalf("failed launch token = %q, want empty", got)
	}
}

func TestRuntimeInvalidatesControlTokenWhenTUIEnds(t *testing.T) {
	t.Parallel()

	t.Run("disconnected", func(t *testing.T) {
		runtime := newStartedRuntime(t, RuntimeOptions{})
		launch, alreadyOpen, err := runtime.beginTUILaunch()
		if err != nil || alreadyOpen {
			t.Fatalf("beginTUILaunch() = (%#v, %t, %v)", launch, alreadyOpen, err)
		}
		client := ipc.NewClient(runtime.SocketPath(), launch.token)
		if err := client.Call(context.Background(), "tui.connected", nil, &struct{}{}); err != nil {
			t.Fatalf("tui.connected error = %v", err)
		}
		if err := client.Call(context.Background(), "tui.disconnected", nil, &struct{}{}); err != nil {
			t.Fatalf("tui.disconnected error = %v", err)
		}
		assertUnauthenticatedControl(t, runtime, launch.token)
	})

	t.Run("heartbeat_expired", func(t *testing.T) {
		runtime := newStartedRuntime(t, RuntimeOptions{})
		launch, alreadyOpen, err := runtime.beginTUILaunch()
		if err != nil || alreadyOpen {
			t.Fatalf("beginTUILaunch() = (%#v, %t, %v)", launch, alreadyOpen, err)
		}
		if err := ipc.NewClient(runtime.SocketPath(), launch.token).Call(context.Background(), "tui.connected", nil, &struct{}{}); err != nil {
			t.Fatalf("tui.connected error = %v", err)
		}
		if runtime.hasActiveTUI(time.Now().Add(10*time.Second + time.Nanosecond)) {
			t.Fatal("hasActiveTUI() = true after the heartbeat deadline")
		}
		assertUnauthenticatedControl(t, runtime, launch.token)
	})
}

func newStartedRuntime(t *testing.T, options RuntimeOptions) *Runtime {
	t.Helper()
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	options.Roots = roots
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	return runtime
}

func assertUnauthenticatedControl(t *testing.T, runtime *Runtime, token string) {
	t.Helper()
	var status control.Status
	err := ipc.NewClient(runtime.SocketPath(), token).Call(context.Background(), "status", nil, &status)
	if !errors.Is(err, ipc.ErrUnauthorized) {
		t.Fatalf("token %q status error = %v, want ErrUnauthorized", token, err)
	}
}

func assertControlTokenAccepted(t *testing.T, runtime *Runtime, token string) {
	t.Helper()
	var status control.Status
	if err := ipc.NewClient(runtime.SocketPath(), token).Call(context.Background(), "status", nil, &status); err != nil {
		t.Fatalf("token %q status error = %v", token, err)
	}
}

func assertControlEndpointClosed(t *testing.T, endpoint, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var result control.Status
	if err := ipc.NewClient(endpoint, token).Call(ctx, "status", nil, &result); err == nil {
		t.Fatalf("control endpoint %q accepted a request after shutdown", endpoint)
	}
}

func waitForBridgeEndpoint(t *testing.T, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		client, err := bridge.Connect(context.Background(), endpoint)
		if err == nil {
			_ = client.Close(context.Background())
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge endpoint %q did not become ready: %v", endpoint, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertBridgeEndpointClosed(t *testing.T, endpoint string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := bridge.Connect(ctx, endpoint)
	if err == nil {
		_ = client.Close(context.Background())
		t.Fatalf("bridge endpoint %q accepted a connection after shutdown", endpoint)
	}
}

func TestRuntimePrepareForceStopRecordsUnknownOutcome(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	runtime.prepareForceStop(context.Background())
	contents, err := os.ReadFile(filepath.Join(roots.ConfigDir, auditlog.FileName))
	if err != nil {
		t.Fatalf("read force-stop audit: %v", err)
	}
	if !bytes.Contains(contents, []byte(`"action":"daemon_force_stop"`)) ||
		!bytes.Contains(contents, []byte(`"status":"outcome_unknown"`)) ||
		!bytes.Contains(contents, []byte(`"in_flight_operations_may_be_unknown"`)) {
		t.Fatalf("force-stop audit = %s", contents)
	}
}

func TestRuntimeSSHIntegration(t *testing.T) {
	host, port, username, password, ok := runtimeSSHIntegrationEnvironment(t)
	if !ok {
		t.Skip("direct SSH integration environment is not configured")
	}

	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{
		Roots: roots,
		TUIOpener: func() error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	controlClient := ipc.NewClient(runtime.SocketPath(), runtime.Token())
	var unlocked control.UnlockResult
	if err := controlClient.Call(ctx, "unlock", control.UnlockParams{MasterPassword: "stage17-runtime-test-master"}, &unlocked); err != nil {
		t.Fatalf("unlock error = %v", err)
	}
	if !unlocked.Unlocked {
		t.Fatalf("unlock result = %#v", unlocked)
	}
	target := store.SSHTarget{
		IP: host, Mode: store.SSHDirect, SSHPort: port, LoginUsername: username,
		CredentialID: "stage17-ssh", Description: "stage17 integration", Enabled: true,
	}
	var fingerprint control.SSHTestResult
	if err := controlClient.Call(ctx, "ssh.test_target", control.SSHTestParams{Target: target, Password: password}, &fingerprint); err != nil {
		t.Fatalf("initial ssh.test_target error = %v", err)
	}
	if !fingerprint.RequiresFingerprintConfirmation || fingerprint.Fingerprint == "" {
		t.Fatalf("initial fingerprint result = %#v", fingerprint)
	}
	if err := controlClient.Call(ctx, "ssh.test_target", control.SSHTestParams{
		Target: target, Password: password, ConfirmedFingerprint: fingerprint.Fingerprint,
	}, &fingerprint); err != nil {
		t.Fatalf("confirmed ssh.test_target error = %v", err)
	}
	if fingerprint.RequiresFingerprintConfirmation {
		t.Fatalf("confirmed fingerprint result = %#v", fingerprint)
	}
	if err := controlClient.Call(ctx, "target.upsert_ssh", control.UpsertSSHTargetParams{
		Target: target, Password: password, ConfirmedFingerprint: fingerprint.Fingerprint,
	}, &struct{}{}); err != nil {
		t.Fatalf("target.upsert_ssh error = %v", err)
	}

	bridgeClient, err := bridge.Connect(ctx, runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer bridgeClient.Close(context.Background())
	var targets runner.TargetsResult
	if err := bridgeClient.Call(ctx, bridgeMethodListTargets, struct{}{}, &targets); err != nil {
		t.Fatalf("targets.list error = %v", err)
	}
	if len(targets.SSH) != 1 || targets.SSH[0].IP != host {
		t.Fatalf("targets = %#v", targets)
	}
	var result runner.Result
	if err := bridgeClient.Call(ctx, bridgeMethodRunSSH, runner.SSHRequest{Target: host, Command: "free -m"}, &result); err != nil {
		t.Fatalf("ssh.run error = %v", err)
	}
	if result.Status != runner.StatusCompleted || result.SSH == nil || !strings.Contains(result.SSH.Stdout, "Mem:") || !result.UntrustedRemoteOutput {
		t.Fatalf("ssh.run result = %#v", result)
	}
	contents, err := os.ReadFile(runtime.audit.Path())
	if err != nil {
		t.Fatalf("ReadFile(audit.log) error = %v", err)
	}
	if !strings.Contains(string(contents), `"ssh_command":"free -m"`) || strings.Contains(string(contents), "Mem:") {
		t.Fatalf("audit log = %s", contents)
	}
}

func runtimeSSHIntegrationEnvironment(t *testing.T) (host string, port int, username, password string, ok bool) {
	t.Helper()
	host = os.Getenv("SSH_MCP_TEST_SSH_HOST")
	portText := os.Getenv("SSH_MCP_TEST_SSH_PORT")
	username = os.Getenv("SSH_MCP_TEST_SSH_USERNAME")
	password = os.Getenv("SSH_MCP_TEST_SSH_PASSWORD")
	if host == "" || portText == "" || username == "" || password == "" {
		return "", 0, "", "", false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("invalid SSH_MCP_TEST_SSH_PORT")
	}
	return host, port, username, password, true
}

func TestRuntimeRejectsSecondInstanceForSameStateDirectory(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	first, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime(first) error = %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	before := sessionCount(t, filepath.Join(roots.ConfigDir, stateFileName))

	if _, err := NewRuntime(RuntimeOptions{Roots: roots}); !errors.Is(err, instance.ErrAlreadyRunning) {
		t.Fatalf("NewRuntime(second) error = %v, want ErrAlreadyRunning", err)
	}
	after := sessionCount(t, filepath.Join(roots.ConfigDir, stateFileName))
	if after != before {
		t.Errorf("rejected instance changed session count from %d to %d", before, after)
	}
}

func TestRuntimeClosesIsolatedConnectionsOnLockSessionInvalidationAndShutdown(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	dialer := &runtimeTestSSHDialer{}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, sshDialer: dialer})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	target, vault := prepareRuntimeIsolatedTarget(t, runtime)

	if _, err := runtime.ssh.ExecuteIsolated(context.Background(), vault, target, policy.Version, "free -m", false, 1024); err != nil {
		t.Fatalf("first ExecuteIsolated() error = %v", err)
	}
	first := dialer.connection(0)
	if _, err := runtime.handleControl(context.Background(), "lock", nil); err != nil {
		t.Fatalf("handleControl(lock) error = %v", err)
	}
	if !first.closed {
		t.Fatal("lock did not close the isolated connection")
	}

	unlockParams, err := json.Marshal(control.UnlockParams{MasterPassword: "master-password"})
	if err != nil {
		t.Fatalf("Marshal unlock params error = %v", err)
	}
	if _, err := runtime.handleControl(context.Background(), "unlock", unlockParams); err != nil {
		t.Fatalf("handleControl(unlock) error = %v", err)
	}
	vault, err = runtime.sessions.Vault()
	if err != nil {
		t.Fatalf("Vault() error = %v", err)
	}
	if _, err := runtime.ssh.ExecuteIsolated(context.Background(), vault, target, policy.Version, "uptime", false, 1024); err != nil {
		t.Fatalf("second ExecuteIsolated() error = %v", err)
	}
	second := dialer.connection(1)
	workSession, err := runtime.workSessions.Open(target.IP, target.Revision, policy.Version)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	runtime.workSessions.Close(workSession.ID)
	if !second.closed {
		t.Fatal("work-session invalidation did not close the isolated connection")
	}

	if _, err := runtime.ssh.ExecuteIsolated(context.Background(), vault, target, policy.Version, "hostname", false, 1024); err != nil {
		t.Fatalf("third ExecuteIsolated() error = %v", err)
	}
	third := dialer.connection(2)
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !third.closed {
		t.Fatal("daemon shutdown did not close the isolated connection")
	}
}

func TestRuntimeLockSuspendsDirectDiagnosticsBeforeLockingVault(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	connection := &runtimeBlockingSSHConnection{
		started: make(chan string, 1), release: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, sshDialer: runtimeBlockingSSHDialer{connection: connection}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() {
		select {
		case connection.release <- struct{}{}:
		default:
		}
		_ = runtime.Close()
	})
	target, vault := prepareRuntimeIsolatedTarget(t, runtime)

	executed := make(chan error, 1)
	go func() {
		_, err := runtime.ssh.ExecuteIsolated(context.Background(), vault, target, policy.Version, "free -m", false, 1024)
		executed <- err
	}()
	if command := <-connection.started; command != "free -m" {
		t.Fatalf("active command = %q", command)
	}

	locked := make(chan error, 1)
	go func() {
		_, err := runtime.handleControl(context.Background(), "lock", nil)
		locked <- err
	}()
	select {
	case <-connection.closed:
	case <-time.After(time.Second):
		t.Fatal("lock did not close the active isolated connection")
	}
	if _, err := runtime.ssh.ExecuteIsolated(context.Background(), vault, target, policy.Version, "uptime", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("ExecuteIsolated() while lock is pending error = %v, want ErrNotDispatched", err)
	}
	select {
	case err := <-locked:
		t.Fatalf("lock completed before the active direct diagnostic ended: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if !runtime.sessions.IsUnlocked() {
		t.Fatal("lock closed the vault before the active direct diagnostic ended")
	}

	connection.release <- struct{}{}
	if err := <-executed; err != nil {
		t.Fatalf("active ExecuteIsolated() error = %v", err)
	}
	if err := <-locked; err != nil {
		t.Fatalf("handleControl(lock) error = %v", err)
	}
	if runtime.sessions.IsUnlocked() {
		t.Fatal("lock did not close the vault after suspending direct diagnostics")
	}
}

func TestRuntimeBridgeCancellationStopsAbandonedSSHRequest(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	auditPath := filepath.Join(roots.ConfigDir, auditlog.FileName)
	connection := &runtimeBlockingSSHConnection{
		started: make(chan string, 1), release: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, sshDialer: runtimeBlockingSSHDialer{connection: connection}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() {
		select {
		case connection.release <- struct{}{}:
		default:
		}
		_ = runtime.Close()
	})
	target, _ := prepareRuntimeIsolatedTarget(t, runtime)
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })

	t.Run("派发前取消不会触发远端操作", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var result runner.Result
		if err := client.Call(ctx, bridgeMethodRunSSH, runner.SSHRequest{Target: target.IP, Command: "free -m"}, &result); !errors.Is(err, context.Canceled) {
			t.Fatalf("取消前的 bridge 调用错误 = %v，期望 context.Canceled", err)
		}
		select {
		case command := <-connection.started:
			t.Fatalf("已取消的 bridge 调用仍派发远端命令 %q", command)
		default:
		}
	})

	t.Run("派发后取消记录结果未知", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		callDone := make(chan error, 1)
		go func() {
			var result runner.Result
			callDone <- client.Call(ctx, bridgeMethodRunSSH, runner.SSHRequest{Target: target.IP, Command: "free -m"}, &result)
		}()
		select {
		case command := <-connection.started:
			if command != "free -m" {
				t.Fatalf("派发的远端命令 = %q，期望 free -m", command)
			}
		case <-time.After(time.Second):
			t.Fatal("bridge 调用未进入远端派发")
		}
		cancel()
		select {
		case err := <-callDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("派发后的 bridge 调用错误 = %v，期望 context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("取消后的 bridge 调用未返回")
		}

		deadline := time.Now().Add(time.Second)
		var (
			terminalRecorded bool
			lastAudit        []byte
			lastReadErr      error
		)
		for !terminalRecorded && time.Now().Before(deadline) {
			contents, readErr := os.ReadFile(auditPath)
			if readErr != nil {
				if !errors.Is(readErr, os.ErrNotExist) {
					lastReadErr = readErr
				}
			} else {
				lastAudit = contents
				decoder := json.NewDecoder(bytes.NewReader(contents))
				for {
					var event auditlog.Event
					decodeErr := decoder.Decode(&event)
					if decodeErr != nil {
						break
					}
					if event.Phase == auditlog.PhaseFailed && event.Target.Kind == "ssh" && event.Target.ID == target.IP && event.SSHCommand == "free -m" && event.RemoteExecuted && event.Result.Status == runner.StatusOutcomeUnknown {
						terminalRecorded = true
						break
					}
				}
			}
			if !terminalRecorded {
				time.Sleep(time.Millisecond)
			}
		}
		if !terminalRecorded {
			t.Fatalf("未看到断连后的结果未知终态审计，最后审计日志 = %s，读取错误 = %v", lastAudit, lastReadErr)
		}
	})
}

func prepareRuntimeIsolatedTarget(t *testing.T, runtime *Runtime) (store.SSHTarget, *store.Vault) {
	t.Helper()
	if _, err := runtime.sessions.Unlock(context.Background(), []byte("master-password")); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	vault, err := runtime.sessions.Vault()
	if err != nil {
		t.Fatalf("Vault() error = %v", err)
	}
	if err := vault.PutCredential(context.Background(), "ssh-runtime", "ssh", []byte("password")); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	target := store.SSHTarget{IP: "192.0.2.90", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-runtime", Enabled: true, IdentityStatus: store.SSHIdentityVerified}
	if err := runtime.store.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	if err := runtime.store.PinInitialHostKey(context.Background(), target.IP, target.SSHPort, "SHA256:runtime"); err != nil {
		t.Fatalf("PinInitialHostKey() error = %v", err)
	}
	target, err = runtime.store.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	return target, vault
}

type fakeSSHConnectionCloser struct {
	invalidated []string
	activated   []string
}

func (c *fakeSSHConnectionCloser) InvalidateTarget(target string) {
	c.invalidated = append(c.invalidated, target)
}
func (c *fakeSSHConnectionCloser) ActivateTarget(target string) {
	c.activated = append(c.activated, target)
}
func (c *fakeSSHConnectionCloser) CloseTarget(string) {}
func (c *fakeSSHConnectionCloser) Suspend() error     { return nil }
func (c *fakeSSHConnectionCloser) Resume()            {}
func (c *fakeSSHConnectionCloser) CloseAll() error    { return nil }
func (c *fakeSSHConnectionCloser) Close() error       { return nil }

type runtimeTestSSHDialer struct {
	connections []*runtimeTestSSHConnection
}

func (d *runtimeTestSSHDialer) Dial(context.Context, sshtransport.Endpoint) (sshservice.IsolatedConnection, error) {
	connection := &runtimeTestSSHConnection{}
	d.connections = append(d.connections, connection)
	return connection, nil
}

func (d *runtimeTestSSHDialer) connection(index int) *runtimeTestSSHConnection {
	if index < 0 || index >= len(d.connections) {
		panic("isolated SSH connection index out of range")
	}
	return d.connections[index]
}

type runtimeTestSSHConnection struct {
	closed bool
}

func (*runtimeTestSSHConnection) Execute(context.Context, string, bool, int) (sshtransport.ExecutionResult, error) {
	return sshtransport.ExecutionResult{}, nil
}

func (c *runtimeTestSSHConnection) Close() error {
	c.closed = true
	return nil
}

type runtimeBlockingSSHDialer struct {
	connection *runtimeBlockingSSHConnection
}

func (d runtimeBlockingSSHDialer) Dial(context.Context, sshtransport.Endpoint) (sshservice.IsolatedConnection, error) {
	return d.connection, nil
}

type runtimeBlockingSSHConnection struct {
	started chan string
	release chan struct{}
	closed  chan struct{}
	close   sync.Once
}

func (c *runtimeBlockingSSHConnection) Execute(ctx context.Context, command string, _ bool, _ int) (sshtransport.ExecutionResult, error) {
	c.started <- command
	select {
	case <-ctx.Done():
		return sshtransport.ExecutionResult{}, ctx.Err()
	case <-c.release:
		return sshtransport.ExecutionResult{Stdout: command}, nil
	}
}

func (c *runtimeBlockingSSHConnection) Close() error {
	c.close.Do(func() { close(c.closed) })
	return nil
}

func sessionCount(t *testing.T, path string) int {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open state database: %v", err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil {
		t.Fatalf("count state sessions: %v", err)
	}
	return count
}

func TestDaemonServesMultipleBridgeClientsWithoutSharingSQLite(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runDaemon(ctx, RuntimeOptions{Roots: roots, DaemonIdleTimeout: time.Hour})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("runDaemon() error = %v", err)
		}
	})

	socketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	waitForBridgeEndpoint(t, socketPath)
	first, err := bridge.Connect(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("Connect(first) error = %v", err)
	}
	defer first.Close(context.Background())
	second, err := bridge.Connect(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("Connect(second) error = %v", err)
	}
	defer second.Close(context.Background())
	var status DaemonStatus
	if err := first.Call(context.Background(), bridgeMethodStatus, struct{}{}, &status); err != nil {
		t.Fatalf("status call error = %v", err)
	}
	if status.ActiveBridgeSessions != 1 {
		t.Fatalf("ActiveBridgeSessions = %d, want 1 external bridge session", status.ActiveBridgeSessions)
	}
}

func TestDaemonStatusExcludesItsTemporaryBridgeConnection(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, RuntimeOptions{Roots: roots, DaemonIdleTimeout: time.Hour}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("runDaemon() error = %v", err)
		}
	})

	waitForBridgeEndpoint(t, filepath.Join(roots.RuntimeDir, bridgeSockName))
	status, err := daemonStatus(context.Background(), RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("daemonStatus() error = %v", err)
	}
	if !status.Running || status.ActiveBridgeSessions != 0 {
		t.Fatalf("daemon status = %#v, want no external bridge sessions", status)
	}
}

func TestConnectOrStartDaemonRequiresHealthyBridge(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	server := bridge.NewServer(bridge.ServerOptions{
		SocketPath: filepath.Join(roots.RuntimeDir, bridgeSockName),
		Handler: bridge.HandlerFunc(func(context.Context, bridge.Session, string, json.RawMessage) (any, error) {
			return nil, bridge.ErrMethodNotFound
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if executor, err := connectOrStartDaemon(ctx, RuntimeOptions{Roots: roots}); err == nil {
		_ = executor.Close(context.Background())
		t.Fatal("connectOrStartDaemon() succeeded with an unhealthy bridge")
	}
}

func TestConnectOrStartDaemonReturnsDaemonStartupFailure(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	want := errors.New("acquire ssh-mcp instance lock: ssh-mcp is already running")
	_, err = connectOrStartDaemon(context.Background(), RuntimeOptions{
		Roots: roots,
		daemonStarter: func(context.Context) error {
			return want
		},
	})
	if !errors.Is(err, want) {
		t.Fatalf("connectOrStartDaemon() error = %v, want daemon startup failure", err)
	}
}

func TestWaitForDaemonStartupAcceptsReadyAndReportsChildFailure(t *testing.T) {
	t.Run("ready", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe() error = %v", err)
		}
		if _, err := writer.WriteString(daemonStartupReady); err != nil {
			t.Fatalf("WriteString() error = %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		defer reader.Close()
		if err := waitForDaemonStartup(context.Background(), reader); err != nil {
			t.Fatalf("waitForDaemonStartup() error = %v", err)
		}
	})

	t.Run("startup failure", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("Pipe() error = %v", err)
		}
		t.Setenv(daemonStartupFDEnv, strconv.Itoa(int(writer.Fd())))
		reportDaemonStartup(errors.New("acquire ssh-mcp instance lock: ssh-mcp is already running"))
		defer reader.Close()
		err = waitForDaemonStartup(context.Background(), reader)
		if err == nil || !strings.Contains(err.Error(), "instance lock") {
			t.Fatalf("waitForDaemonStartup() error = %v, want startup failure detail", err)
		}
	})
}

func TestBridgeListTargetsReturnsWithoutTUISessionApproval(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	openedTUI := 0
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		openedTUI++
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	var targets runner.TargetsResult
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := client.Call(ctx, bridgeMethodListTargets, struct{}{}, &targets); err != nil {
		t.Fatalf("ListTargets() error = %v", err)
	}
	if openedTUI != 0 || len(targets.SSH) != 0 || len(targets.Databases) != 0 {
		t.Fatalf("TUI opens = %d, targets = %#v", openedTUI, targets)
	}
	if _, err := os.Stat(runtime.audit.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ListTargets() unexpectedly created an audit log: %v", err)
	}
}

func TestBridgeRejectsRemovedLegacyExecutionMethods(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	for _, method := range []string{"operation.approve", "maintenance.start"} {
		var result runner.Result
		if err := client.Call(context.Background(), method, struct{}{}, &result); !errors.Is(err, bridge.ErrMethodNotFound) {
			t.Fatalf("Call(%q) error = %v，期望 ErrMethodNotFound", method, err)
		}
	}
}

func TestExclusiveMaintenanceRejectsActiveBridgeSessions(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	called := false
	_, err = runtime.withExclusiveMaintenance(func() (any, error) {
		called = true
		return struct{}{}, nil
	})
	if !errors.Is(err, ErrMaintenanceBusy) || called {
		t.Fatalf("withExclusiveMaintenance() error = %v, called = %t", err, called)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for runtime.ActiveBridgeSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := runtime.withExclusiveMaintenance(func() (any, error) {
		called = true
		return struct{}{}, nil
	}); err != nil {
		t.Fatalf("withExclusiveMaintenance() after bridge close error = %v", err)
	}
	if !called {
		t.Fatal("exclusive maintenance was not called after bridge closed")
	}
}

func TestUnregisteredTargetOpensTUIAndReturnsStructuredStatusImmediately(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	openedTUI := 0
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		openedTUI++
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := runtime.runSSHForBridge(ctx, bridge.Session{ID: "test-bridge"}, runner.SSHRequest{Target: "192.0.2.10", Command: "free -m"})
	if err != nil {
		t.Fatalf("runSSHForBridge(unregistered) error = %v", err)
	}
	if result.Status != runner.StatusTargetNotFound {
		t.Fatalf("runSSHForBridge(unregistered) = %#v, want target_not_found", result)
	}
	if openedTUI != 1 {
		t.Fatalf("TUI opens = %d, want 1", openedTUI)
	}
}

func TestUnregisteredDatabaseOpensTUIAndReturnsStructuredStatusImmediately(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	openedTUI := 0
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		openedTUI++
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := runtime.runSQLForBridge(ctx, bridge.Session{ID: "test-bridge"}, runner.SQLRequest{Target: "192.0.2.20:5432", Statement: "SELECT 1"})
	if err != nil {
		t.Fatalf("runSQLForBridge(unregistered) error = %v", err)
	}
	if result.Status != runner.StatusDatabaseNotFound {
		t.Fatalf("runSQLForBridge(unregistered) = %#v, want database_not_found", result)
	}
	if openedTUI != 1 {
		t.Fatalf("TUI opens = %d, want 1", openedTUI)
	}
}

func TestAuditBridgeTargetDecisionRetainsTargetStatusWhenAuditWriteFails(t *testing.T) {
	t.Parallel()

	audit := auditlog.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err := audit.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	runtime := &Runtime{audit: audit}
	for _, test := range []struct {
		name       string
		targetKind string
		status     string
		reason     string
	}{
		{name: "missing database", targetKind: "database", status: runner.StatusDatabaseNotFound, reason: "target_not_found"},
		{name: "disabled SSH", targetKind: "ssh", status: runner.StatusRejected, reason: "target_disabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := runtime.auditBridgeTargetDecision(context.Background(), bridge.Session{ID: "test-bridge"}, test.targetKind, "192.0.2.20:5432", test.status, test.reason)
			if err != nil {
				t.Fatalf("auditBridgeTargetDecision() error = %v", err)
			}
			if result.Status != test.status || result.ExecutionOutcome != runner.StatusNotDispatched || result.AuditOutcome != runner.AuditOutcomeFailed || !result.AuditWriteFailed {
				t.Fatalf("audit failure result = %#v", result)
			}
			if result.Status == runner.StatusAuditWriteFailed {
				t.Fatalf("audit failure overwrote target result: %#v", result)
			}
		})
	}
}

func TestDaemonStopsAfterConfiguredBridgeIdleTimeout(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := runDaemon(context.Background(), RuntimeOptions{Roots: roots, DaemonIdleTimeout: 10 * time.Millisecond}); err != nil {
		t.Fatalf("runDaemon() error = %v", err)
	}
	assertBridgeEndpointClosed(t, filepath.Join(roots.RuntimeDir, bridgeSockName))
}

func TestRuntimeDefersShutdownUntilBridgeResponseCompletes(t *testing.T) {
	runtime := &Runtime{shutdownRequested: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := runtime.handleBridge(ctx, bridge.Session{}, bridgeMethodShutdown, nil); err != nil {
		t.Fatalf("shutdown bridge handler error = %v", err)
	}
	select {
	case <-runtime.shutdownRequested:
		t.Fatal("shutdown was requested before the bridge response completed")
	default:
	}

	cancel()
	select {
	case <-runtime.shutdownRequested:
	case <-time.After(time.Second):
		t.Fatal("shutdown was not requested after bridge response completion")
	}
}

func TestRuntimeWaitForIdleIgnoresIdleBridgeSession(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, DaemonIdleTimeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := runtime.WaitForIdle(ctx); err != nil {
		t.Fatalf("WaitForIdle() error = %v, want daemon exit despite an idle bridge session", err)
	}
}

func TestRuntimeWaitForIdleResetsForActualBridgeRequest(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, DaemonIdleTimeout: 80 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	done := make(chan error, 1)
	go func() { done <- runtime.WaitForIdle(context.Background()) }()
	time.Sleep(45 * time.Millisecond)
	var status DaemonStatus
	if err := client.Call(context.Background(), bridgeMethodStatus, struct{}{}, &status); err != nil {
		t.Fatalf("daemon.status error = %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("WaitForIdle() returned early after a bridge request: %v", err)
	case <-time.After(45 * time.Millisecond):
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitForIdle() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("WaitForIdle() did not exit after the reset idle interval")
	}
}

func TestRuntimeWaitForIdleWaitsForConnectedTUI(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, DaemonIdleTimeout: 30 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client := ipc.NewClient(runtime.SocketPath(), runtime.Token())
	if err := client.Call(context.Background(), "tui.connected", nil, &struct{}{}); err != nil {
		t.Fatalf("tui.connected error = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- runtime.WaitForIdle(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("WaitForIdle() returned while TUI was active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := client.Call(context.Background(), "tui.disconnected", nil, &struct{}{}); err != nil {
		t.Fatalf("tui.disconnected error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitForIdle() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("WaitForIdle() did not exit after the TUI closed")
	}
}

func TestBridgeOpenTUIWaitsForConnection(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	var runtime *Runtime
	runtime, err = NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _ = runtime.handleControl(context.Background(), "tui.connected", nil)
		}()
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := newBridgeExecutor(client).OpenTUI(ctx, desktopEnvironment{}); err != nil {
		t.Fatalf("OpenTUI() error = %v", err)
	}
}

func TestBridgeOpenTUIPersistsDesktopEnvironment(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	var runtime *Runtime
	runtime, err = NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _ = runtime.handleControl(context.Background(), "tui.connected", nil)
		}()
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())
	desktop := desktopEnvironment{Display: ":1", DBusSessionBusAddress: "unix:path=/run/user/1000/bus", TermProgram: "Windows Terminal", WTSession: "test-session"}
	runtime.mu.Lock()
	runtime.tuiLaunching = true
	runtime.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := newBridgeExecutor(client).OpenTUI(ctx, desktop); err != nil {
		t.Fatalf("OpenTUI() error = %v", err)
	}
	if got := runtime.desktopEnvironment(); got != desktop {
		t.Fatalf("desktop environment = %#v, want %#v", got, desktop)
	}
	persisted, err := loadDesktopEnvironment(filepath.Join(roots.RuntimeDir, desktopEnvironmentFileName))
	if err != nil {
		t.Fatalf("loadDesktopEnvironment() error = %v", err)
	}
	if persisted != desktop {
		t.Fatalf("persisted desktop environment = %#v, want %#v", persisted, desktop)
	}
}

func TestBridgeOpenTUIReportsConnectionTimeout(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{
		Roots:             roots,
		TUIConnectTimeout: 20 * time.Millisecond,
		TUIOpener:         func() error { return nil },
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := bridge.Connect(context.Background(), runtime.BridgeSocketPath())
	if err != nil {
		t.Fatalf("bridge.Connect() error = %v", err)
	}
	defer client.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = newBridgeExecutor(client).OpenTUI(ctx, desktopEnvironment{})
	if !errors.Is(err, bridge.ErrTUIConnectionTimeout) {
		t.Fatalf("OpenTUI() error = %v, want ErrTUIConnectionTimeout", err)
	}
}

func TestRunManageReturnsAfterTUIConnection(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	var runtime *Runtime
	runtime, err = NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _ = runtime.handleControl(context.Background(), "tui.connected", nil)
		}()
		return nil
	}})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := runManage(ctx, RuntimeOptions{Roots: roots}); err != nil {
		t.Fatalf("runManage() error = %v", err)
	}
}

func TestRuntimeOpenTUIAndWaitReportsMissingConnection(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots, TUIOpener: func() error { return nil }})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err = runtime.OpenTUIAndWait(ctx)
	if !errors.Is(err, ErrTUIConnectionTimeout) {
		t.Fatalf("OpenTUIAndWait() error = %v, want ErrTUIConnectionTimeout", err)
	}
}

func TestRuntimeUsesFileAuditInsteadOfSQLiteAuditTable(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Roots: roots})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()
	if runtime.audit.Path() != filepath.Join(roots.ConfigDir, "audit.log") {
		t.Fatalf("audit path = %q", runtime.audit.Path())
	}
}
