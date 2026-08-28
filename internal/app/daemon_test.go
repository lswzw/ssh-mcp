package app

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestPrepareDaemonStopSendsForcePreparationBeforeClosingCapability(t *testing.T) {
	t.Parallel()

	executor := &fakeDaemonStopExecutor{}
	if err := prepareDaemonStop(context.Background(), executor, true); err != nil {
		t.Fatalf("prepareDaemonStop() error = %v", err)
	}
	if want := []string{"status", "prepare", "shutdown", "close"}; !slices.Equal(executor.calls, want) {
		t.Fatalf("调用顺序 = %#v，期望 %#v", executor.calls, want)
	}
}

func TestPrepareDaemonStopRejectsNormalStopWithActiveBridgeSession(t *testing.T) {
	t.Parallel()

	executor := &fakeDaemonStopExecutor{status: DaemonStatus{ActiveBridgeSessions: 1}}
	err := prepareDaemonStop(context.Background(), executor, false)
	if !errors.Is(err, ErrDaemonBusy) {
		t.Fatalf("prepareDaemonStop() error = %v，期望 %v", err, ErrDaemonBusy)
	}
	if want := []string{"status", "close"}; !slices.Equal(executor.calls, want) {
		t.Fatalf("调用顺序 = %#v，期望 %#v", executor.calls, want)
	}
}

func TestPrepareDaemonStopAcknowledgesShutdownBeforeCleanup(t *testing.T) {
	t.Parallel()

	executor := &fakeDaemonStopExecutor{}
	if err := prepareDaemonStop(context.Background(), executor, false); err != nil {
		t.Fatalf("prepareDaemonStop() error = %v", err)
	}
	if want := []string{"status", "shutdown", "close"}; !slices.Equal(executor.calls, want) {
		t.Fatalf("调用顺序 = %#v，期望 %#v", executor.calls, want)
	}
}

func TestPrepareDaemonStopDoesNotMaskAcknowledgedShutdownWithCleanupError(t *testing.T) {
	t.Parallel()

	executor := &fakeDaemonStopExecutor{closeErr: errors.New("bridge endpoint closed")}
	if err := prepareDaemonStop(context.Background(), executor, false); err != nil {
		t.Fatalf("prepareDaemonStop() error = %v, want nil after acknowledged shutdown", err)
	}
	if want := []string{"status", "shutdown", "close"}; !slices.Equal(executor.calls, want) {
		t.Fatalf("调用顺序 = %#v，期望 %#v", executor.calls, want)
	}
}

func TestWaitForDaemonProcessExitPollsUntilTerminationIsObservable(t *testing.T) {
	t.Parallel()

	marker := daemonPIDMarker{PID: 4242, StartTime: 171717}
	checks := 0
	exited, err := waitForDaemonProcessExit(
		context.Background(),
		marker,
		time.Now().Add(time.Second),
		time.Nanosecond,
		func(got daemonPIDMarker) (bool, error) {
			if got != marker {
				t.Fatalf("checked marker = %#v, want %#v", got, marker)
			}
			checks++
			return checks == 3, nil
		},
	)
	if err != nil {
		t.Fatalf("waitForDaemonProcessExit() error = %v", err)
	}
	if !exited {
		t.Fatal("waitForDaemonProcessExit() = false, want true")
	}
	if checks != 3 {
		t.Fatalf("exit checks = %d, want 3", checks)
	}
}

type fakeDaemonStopExecutor struct {
	status   DaemonStatus
	calls    []string
	closeErr error
}

func (e *fakeDaemonStopExecutor) Status(context.Context) (DaemonStatus, error) {
	e.calls = append(e.calls, "status")
	return e.status, nil
}

func (e *fakeDaemonStopExecutor) PrepareForceStop(context.Context) error {
	e.calls = append(e.calls, "prepare")
	return nil
}

func (e *fakeDaemonStopExecutor) Shutdown(context.Context) error {
	e.calls = append(e.calls, "shutdown")
	return nil
}

func (e *fakeDaemonStopExecutor) Close(context.Context) error {
	e.calls = append(e.calls, "close")
	return e.closeErr
}
