package runner

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEngineDirectSQLStopsCanceledWorkBeforeRemoteDispatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := newFakeDependencies()
	result, err := deps.engine().RunSQL(ctx, SQLRequest{
		Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1",
	})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusNotDispatched || result.RemoteExecuted || deps.database.queryCalls != 0 {
		t.Fatalf("RunSQL() = %#v，数据库 = %#v", result, deps.database)
	}
}

func TestEngineLockDispatchRejectsNewRemoteDispatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		run  func(*Engine) (Result, error)
	}{
		{name: "SSH", run: func(engine *Engine) (Result, error) {
			return engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
		}},
		{name: "SQL", run: func(engine *Engine) (Result, error) {
			return engine.RunSQL(context.Background(), SQLRequest{Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := newFakeDependencies()
			engine := deps.engine()
			if err := engine.LockDispatch(context.Background()); err != nil {
				t.Fatalf("LockDispatch() error = %v", err)
			}
			defer engine.UnlockDispatch()

			result, err := test.run(engine)
			if err != nil {
				t.Fatalf("执行 error = %v", err)
			}
			if result.Status != StatusNotDispatched || result.RemoteExecuted {
				t.Fatalf("锁定后的结果 = %#v", result)
			}
		})
	}
}

func TestEngineLockDispatchWaitsForInFlightSSHRemoteDispatch(t *testing.T) {
	deps := newFakeDependencies()
	releaseRemote := make(chan struct{})
	deps.ssh.waitForRelease = releaseRemote
	started := make(chan struct{})
	deps.ssh.onExecute = func() { close(started) }
	engine := deps.engine()

	runDone := make(chan Result, 1)
	go func() {
		result, err := engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
		if err != nil {
			t.Errorf("RunSSH() error = %v", err)
		}
		runDone <- result
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SSH 未进入远端派发")
	}

	lockDone := make(chan error, 1)
	go func() { lockDone <- engine.LockDispatch(context.Background()) }()
	select {
	case err := <-lockDone:
		t.Fatalf("LockDispatch() 提前返回：%v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseRemote)
	if result := <-runDone; result.Status != StatusCompleted || !result.RemoteExecuted {
		t.Fatalf("RunSSH() = %#v", result)
	}
	select {
	case err := <-lockDone:
		if err != nil {
			t.Fatalf("LockDispatch() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LockDispatch() 未等待在途操作完成")
	}
}

func TestEngineAuditFailureDoesNotBlockDirectDispatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		run  func(*Engine) (Result, error)
	}{
		{name: "SSH", run: func(engine *Engine) (Result, error) {
			return engine.RunSSH(context.Background(), SSHRequest{Target: "192.0.2.10", Command: "free -m"})
		}},
		{name: "SQL", run: func(engine *Engine) (Result, error) {
			return engine.RunSQL(context.Background(), SQLRequest{Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := newFakeDependencies()
			deps.audit.err = errors.New("审计不可写")
			result, err := test.run(deps.engine())
			if err != nil {
				t.Fatalf("执行 error = %v", err)
			}
			if result.Status != StatusCompleted || result.ExecutionOutcome != StatusCompleted ||
				result.AuditOutcome != AuditOutcomeFailed || !result.AuditWriteFailed || !result.RemoteExecuted {
				t.Fatalf("审计失败结果 = %#v", result)
			}
		})
	}
}

func TestEngineAcceptsExplicitFiniteBudgets(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	result, err := deps.engine().RunSQL(context.Background(), SQLRequest{
		Target: "192.0.2.20:5432", Database: "app", Statement: "SELECT 1",
		Timeout: 2 * time.Minute, MaxRows: 2_000, MaxBytes: 128 << 10,
	})
	if err != nil {
		t.Fatalf("RunSQL() error = %v", err)
	}
	if result.Status != StatusCompleted || !result.RemoteExecuted || deps.database.queryCalls != 1 ||
		deps.database.queryLimits.MaxRows != 2_000 || deps.database.queryLimits.MaxBytes != 128<<10 {
		t.Fatalf("显式有限预算没有直接派发：%#v，数据库 = %#v", result, deps.database)
	}
}
