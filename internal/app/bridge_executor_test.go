package app

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	"ssh-mcp/internal/runner"
)

func TestReconnectingExecutorRetriesUnavailableBridgeOnce(t *testing.T) {
	second := &fakeDaemonToolExecutor{targets: runner.TargetsResult{SSH: []runner.SSHTarget{{IP: "192.0.2.10", Enabled: true}}}}
	connections := 0
	executor := newReconnectingExecutor(RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		connections++
		if connections == 1 {
			return nil, fmt.Errorf("connect to local bridge: %w", syscall.ECONNREFUSED)
		}
		return second, nil
	})

	targets, err := executor.ListTargets(context.Background())
	if err != nil {
		t.Fatalf("ListTargets() error = %v", err)
	}
	if connections != 2 || second.closed {
		t.Fatalf("connections = %d, second closed = %t", connections, second.closed)
	}
	if len(targets.SSH) != 1 || targets.SSH[0].IP != "192.0.2.10" {
		t.Fatalf("targets = %#v", targets)
	}
	if err := executor.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !second.closed {
		t.Fatal("Close() did not revoke the cached bridge capability")
	}
}

func TestReconnectingExecutorReusesOneBridgeCapabilityUntilServeStops(t *testing.T) {
	t.Parallel()

	daemon := &fakeDaemonToolExecutor{targets: runner.TargetsResult{SSH: []runner.SSHTarget{{IP: "192.0.2.10", Enabled: true}}}}
	connections := 0
	executor := newReconnectingExecutor(RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		connections++
		return daemon, nil
	})

	if _, err := executor.ListTargets(context.Background()); err != nil {
		t.Fatalf("first ListTargets() error = %v", err)
	}
	if _, err := executor.ListTargets(context.Background()); err != nil {
		t.Fatalf("second ListTargets() error = %v", err)
	}
	if connections != 1 || daemon.closed {
		t.Fatalf("connections = %d, daemon closed = %t", connections, daemon.closed)
	}
	if err := executor.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !daemon.closed {
		t.Fatal("Close() did not close the cached daemon executor")
	}
}

func TestReconnectingExecutorDoesNotReplaySubmittedRemoteOperation(t *testing.T) {
	first := &fakeDaemonToolExecutor{runSSHErr: fmt.Errorf("read bridge response: %w", syscall.ECONNRESET)}
	second := &fakeDaemonToolExecutor{}
	connections := 0
	executor := newReconnectingExecutor(RuntimeOptions{}, func(context.Context, RuntimeOptions) (daemonToolExecutor, error) {
		connections++
		if connections == 1 {
			return first, nil
		}
		return second, nil
	})

	_, err := executor.RunSSH(context.Background(), runner.SSHRequest{Target: "192.0.2.10", Command: "mkdir -p /data/mysql"})
	if err == nil {
		t.Fatal("RunSSH() succeeded after an indeterminate bridge failure")
	}
	if connections != 1 || !first.closed || second.closed {
		t.Fatalf("connections = %d, first closed = %t, second closed = %t", connections, first.closed, second.closed)
	}
}

type fakeDaemonToolExecutor struct {
	targets        runner.TargetsResult
	listTargetsErr error
	runSSHErr      error
	deployResult   runner.Result
	deployErr      error
	deployRequest  runner.SSHBinaryDeploymentRequest
	deployCalls    int
	closed         bool
	sshRequest     runner.SSHRequest
}

var _ daemonToolExecutor = (*fakeDaemonToolExecutor)(nil)

func (e *fakeDaemonToolExecutor) ListTargets(context.Context) (runner.TargetsResult, error) {
	return e.targets, e.listTargetsErr
}

func (*fakeDaemonToolExecutor) DescribeExecutionSpecification(context.Context, runner.ExecutionSpecificationRequest) (runner.ExecutionSpecification, error) {
	return runner.ExecutionSpecification{}, nil
}

func (*fakeDaemonToolExecutor) ListDatabases(context.Context, runner.DatabaseListRequest) (runner.Result, error) {
	return runner.Result{}, nil
}

func (e *fakeDaemonToolExecutor) RunSSH(_ context.Context, request runner.SSHRequest) (runner.Result, error) {
	e.sshRequest = request
	return runner.Result{}, e.runSSHErr
}

func (*fakeDaemonToolExecutor) ReadSSHFile(context.Context, runner.SSHFileReadRequest) (runner.Result, error) {
	return runner.Result{}, nil
}

func (e *fakeDaemonToolExecutor) DeploySSHBinary(_ context.Context, request runner.SSHBinaryDeploymentRequest) (runner.Result, error) {
	e.deployCalls++
	e.deployRequest = request
	return e.deployResult, e.deployErr
}

func (*fakeDaemonToolExecutor) OpenSSHSession(context.Context, runner.OpenSSHSessionRequest) (runner.SSHSessionResult, error) {
	return runner.SSHSessionResult{}, nil
}

func (*fakeDaemonToolExecutor) SetSSHSessionContext(context.Context, runner.SetSSHSessionContextRequest) (runner.SSHSessionResult, error) {
	return runner.SSHSessionResult{}, nil
}

func (*fakeDaemonToolExecutor) ExecuteSSHSession(context.Context, runner.ExecuteSSHSessionRequest) (runner.Result, error) {
	return runner.Result{}, nil
}

func (*fakeDaemonToolExecutor) CloseSSHSession(context.Context, string) (runner.SSHSessionResult, error) {
	return runner.SSHSessionResult{}, nil
}

func (*fakeDaemonToolExecutor) RunSQL(context.Context, runner.SQLRequest) (runner.Result, error) {
	return runner.Result{}, nil
}

func (e *fakeDaemonToolExecutor) Close(context.Context) error {
	e.closed = true
	return nil
}
