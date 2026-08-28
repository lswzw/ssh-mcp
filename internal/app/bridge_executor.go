package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/control"
	"ssh-mcp/internal/runner"
)

const (
	bridgeMethodStatus            = "daemon.status"
	bridgeMethodPrepareForceStop  = "daemon.force_stop.prepare"
	bridgeMethodShutdown          = "daemon.shutdown"
	bridgeMethodListTargets       = "targets.list"
	bridgeMethodDescribeTarget    = "targets.describe_capability"
	bridgeMethodListDatabases     = "databases.list"
	bridgeMethodRunSSH            = "ssh.run"
	bridgeMethodReadSSHFile       = "ssh.file.read"
	bridgeMethodDeploySSHBinary   = "ssh.binary.deploy"
	bridgeMethodOpenSSHSession    = "ssh.session.open"
	bridgeMethodSetSSHSession     = "ssh.session.set_context"
	bridgeMethodExecuteSSHSession = "ssh.session.execute"
	bridgeMethodCloseSSHSession   = "ssh.session.close"
	bridgeMethodRunSQL            = "sql.run"
	bridgeMethodOpenTUI           = "tui.open"
)

type DaemonStatus struct {
	Running              bool           `json:"running"`
	Control              control.Status `json:"control"`
	ActiveBridgeSessions int            `json:"active_bridge_sessions"`
}

type bridgeExecutor struct {
	client *bridge.Client
}

type daemonToolExecutor interface {
	ToolExecutor
	Close(context.Context) error
}

type daemonConnector func(context.Context, RuntimeOptions) (daemonToolExecutor, error)

// reconnectingExecutor keeps MCP stdio independent from daemon lifetime. It
// reconnects only before submitting a remote operation, never replaying a
// request that may already have reached a remote target.
type reconnectingExecutor struct {
	options   RuntimeOptions
	connector daemonConnector

	mu      sync.Mutex
	closed  bool
	current *daemonConnection
	retired []*daemonConnection
}

type daemonConnection struct {
	executor daemonToolExecutor
	active   int
	retired  bool
}

func newReconnectingExecutor(options RuntimeOptions, connector daemonConnector) *reconnectingExecutor {
	if connector == nil {
		connector = func(ctx context.Context, options RuntimeOptions) (daemonToolExecutor, error) {
			return connectOrStartDaemon(ctx, options)
		}
	}
	return &reconnectingExecutor{options: options, connector: connector}
}

func (e *reconnectingExecutor) ListTargets(ctx context.Context) (runner.TargetsResult, error) {
	var result runner.TargetsResult
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.ListTargets(ctx)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) DescribeExecutionSpecification(ctx context.Context, request runner.ExecutionSpecificationRequest) (runner.ExecutionSpecification, error) {
	var result runner.ExecutionSpecification
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.DescribeExecutionSpecification(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) ListDatabases(ctx context.Context, request runner.DatabaseListRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.ListDatabases(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) RunSSH(ctx context.Context, request runner.SSHRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.RunSSH(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) ReadSSHFile(ctx context.Context, request runner.SSHFileReadRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.ReadSSHFile(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) DeploySSHBinary(ctx context.Context, request runner.SSHBinaryDeploymentRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.DeploySSHBinary(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) OpenSSHSession(ctx context.Context, request runner.OpenSSHSessionRequest) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.OpenSSHSession(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) SetSSHSessionContext(ctx context.Context, request runner.SetSSHSessionContextRequest) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.SetSSHSessionContext(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) ExecuteSSHSession(ctx context.Context, request runner.ExecuteSSHSessionRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.ExecuteSSHSession(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) CloseSSHSession(ctx context.Context, sessionID string) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.CloseSSHSession(ctx, sessionID)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) RunSQL(ctx context.Context, request runner.SQLRequest) (runner.Result, error) {
	var result runner.Result
	err := e.withDaemon(ctx, func(executor daemonToolExecutor) error {
		var err error
		result, err = executor.RunSQL(ctx, request)
		return err
	})
	return result, err
}

func (e *reconnectingExecutor) withDaemon(ctx context.Context, operation func(daemonToolExecutor) error) error {
	connection, err := e.acquireDaemon(ctx)
	if err != nil {
		return err
	}
	retire := false
	defer func() {
		for _, executor := range e.releaseDaemon(connection, retire) {
			_ = executor.Close(context.Background())
		}
	}()

	err = operation(connection.executor)
	if bridgeTransportFailure(err) {
		retire = true
	}
	return err
}

// Close 只在 MCP serve 生命周期结束时撤销其 bridge capability。
func (e *reconnectingExecutor) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	if e.current != nil {
		e.retireLocked(e.current)
		e.current = nil
	}
	toClose := e.collectClosableLocked()
	e.mu.Unlock()
	return closeDaemonExecutors(ctx, toClose)
}

func (e *reconnectingExecutor) acquireDaemon(ctx context.Context) (*daemonConnection, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrDaemonNotRunning
	}
	if e.current != nil {
		e.current.active++
		return e.current, nil
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		executor, err := e.connector(ctx, e.options)
		if err != nil {
			lastErr = err
			if attempt == 0 && retryableDaemonConnection(err) {
				continue
			}
			return nil, err
		}
		if e.closed {
			_ = executor.Close(context.Background())
			return nil, ErrDaemonNotRunning
		}
		connection := &daemonConnection{executor: executor, active: 1}
		e.current = connection
		return connection, nil
	}
	return nil, lastErr
}

func (e *reconnectingExecutor) releaseDaemon(connection *daemonConnection, retire bool) []daemonToolExecutor {
	if e == nil || connection == nil {
		return nil
	}
	e.mu.Lock()
	if retire {
		e.retireLocked(connection)
		if e.current == connection {
			e.current = nil
		}
	}
	if connection.active > 0 {
		connection.active--
	}
	toClose := e.collectClosableLocked()
	e.mu.Unlock()
	return toClose
}

func (e *reconnectingExecutor) retireLocked(connection *daemonConnection) {
	if connection == nil || connection.retired {
		return
	}
	connection.retired = true
	e.retired = append(e.retired, connection)
}

func (e *reconnectingExecutor) collectClosableLocked() []daemonToolExecutor {
	toClose := make([]daemonToolExecutor, 0, len(e.retired))
	remaining := e.retired[:0]
	for _, connection := range e.retired {
		if connection.active == 0 {
			toClose = append(toClose, connection.executor)
			continue
		}
		remaining = append(remaining, connection)
	}
	e.retired = remaining
	return toClose
}

func closeDaemonExecutors(ctx context.Context, executors []daemonToolExecutor) error {
	var firstErr error
	for _, executor := range executors {
		if executor == nil {
			continue
		}
		if err := executor.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func retryableDaemonConnection(err error) bool {
	if err == nil || errors.Is(err, bridge.ErrVersionMismatch) {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "connect to local bridge") || strings.Contains(message, "daemon bridge is unavailable")
}

func bridgeTransportFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, bridge.ErrUnauthorized) || errors.Is(err, bridge.ErrServerNotStarted) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connect to local bridge") ||
		strings.Contains(message, "read bridge response") ||
		strings.Contains(message, "write bridge request") ||
		strings.Contains(message, "set bridge deadline")
}

type closeSSHSessionRequest struct {
	SessionID string `json:"session_id"`
}

type openTUIRequest struct {
	DesktopEnvironment desktopEnvironment `json:"desktop_environment"`
}

func newBridgeExecutor(client *bridge.Client) *bridgeExecutor {
	return &bridgeExecutor{client: client}
}

func (e *bridgeExecutor) ListTargets(ctx context.Context) (runner.TargetsResult, error) {
	var result runner.TargetsResult
	return result, e.call(ctx, bridgeMethodListTargets, struct{}{}, &result)
}

func (e *bridgeExecutor) DescribeExecutionSpecification(ctx context.Context, request runner.ExecutionSpecificationRequest) (runner.ExecutionSpecification, error) {
	var result runner.ExecutionSpecification
	return result, e.call(ctx, bridgeMethodDescribeTarget, request, &result)
}

func (e *bridgeExecutor) ListDatabases(ctx context.Context, request runner.DatabaseListRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodListDatabases, request, &result)
}

func (e *bridgeExecutor) RunSSH(ctx context.Context, request runner.SSHRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodRunSSH, request, &result)
}

func (e *bridgeExecutor) ReadSSHFile(ctx context.Context, request runner.SSHFileReadRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodReadSSHFile, request, &result)
}

func (e *bridgeExecutor) DeploySSHBinary(ctx context.Context, request runner.SSHBinaryDeploymentRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodDeploySSHBinary, request, &result)
}

func (e *bridgeExecutor) OpenSSHSession(ctx context.Context, request runner.OpenSSHSessionRequest) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	return result, e.call(ctx, bridgeMethodOpenSSHSession, request, &result)
}

func (e *bridgeExecutor) SetSSHSessionContext(ctx context.Context, request runner.SetSSHSessionContextRequest) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	return result, e.call(ctx, bridgeMethodSetSSHSession, request, &result)
}

func (e *bridgeExecutor) ExecuteSSHSession(ctx context.Context, request runner.ExecuteSSHSessionRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodExecuteSSHSession, request, &result)
}

func (e *bridgeExecutor) CloseSSHSession(ctx context.Context, sessionID string) (runner.SSHSessionResult, error) {
	var result runner.SSHSessionResult
	return result, e.call(ctx, bridgeMethodCloseSSHSession, closeSSHSessionRequest{SessionID: sessionID}, &result)
}

func (e *bridgeExecutor) RunSQL(ctx context.Context, request runner.SQLRequest) (runner.Result, error) {
	var result runner.Result
	return result, e.call(ctx, bridgeMethodRunSQL, request, &result)
}

func (e *bridgeExecutor) Status(ctx context.Context) (DaemonStatus, error) {
	var result DaemonStatus
	return result, e.call(ctx, bridgeMethodStatus, struct{}{}, &result)
}

func (e *bridgeExecutor) PrepareForceStop(ctx context.Context) error {
	return e.call(ctx, bridgeMethodPrepareForceStop, struct{}{}, &struct{}{})
}

func (e *bridgeExecutor) Shutdown(ctx context.Context) error {
	return e.call(ctx, bridgeMethodShutdown, struct{}{}, &struct{}{})
}

func (e *bridgeExecutor) OpenTUI(ctx context.Context, environment desktopEnvironment) error {
	return e.call(ctx, bridgeMethodOpenTUI, openTUIRequest{DesktopEnvironment: environment}, &struct{}{})
}

func (e *bridgeExecutor) Close(ctx context.Context) error {
	if e == nil || e.client == nil {
		return nil
	}
	return e.client.Close(ctx)
}

func (e *bridgeExecutor) call(ctx context.Context, method string, request, result any) error {
	if e == nil || e.client == nil {
		return fmt.Errorf("daemon bridge is unavailable")
	}
	return e.client.Call(ctx, method, request, result)
}
