package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestClientsReceiveIndependentCapabilitiesAndShareOneServer(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		seenIDs   = make(map[string]bool)
		callCount int
	)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler: HandlerFunc(func(_ context.Context, session Session, method string, params json.RawMessage) (any, error) {
			if method != "echo" {
				return nil, ErrMethodNotFound
			}
			mu.Lock()
			defer mu.Unlock()
			seenIDs[session.ID] = true
			callCount++
			return string(params), nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() 错误 = %v", err)
	}
	defer server.Close()

	first, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(first) error = %v", err)
	}
	defer first.Close(context.Background())
	second, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(second) error = %v", err)
	}
	defer second.Close(context.Background())
	if first.SessionID() == second.SessionID() {
		t.Fatal("independent clients received the same session ID")
	}

	var firstResult, secondResult string
	if err := first.Call(context.Background(), "echo", "first", &firstResult); err != nil {
		t.Fatalf("first Call() error = %v", err)
	}
	if err := second.Call(context.Background(), "echo", "second", &secondResult); err != nil {
		t.Fatalf("second Call() error = %v", err)
	}
	if firstResult != "\"first\"" || secondResult != "\"second\"" {
		t.Fatalf("results = %q, %q", firstResult, secondResult)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenIDs) != 2 || callCount != 2 {
		t.Fatalf("handler sessions = %#v, calls = %d", seenIDs, callCount)
	}
}

func TestServerReportsBridgeProcessIdentityAndRevokesOnClose(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		opened    Session
		closed    Session
		openDone  = make(chan struct{})
		closeDone = make(chan struct{})
	)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionOpened: func(session Session) {
			mu.Lock()
			opened = session
			mu.Unlock()
			close(openDone)
		},
		SessionClosed: func(session Session) {
			mu.Lock()
			closed = session
			mu.Unlock()
			close(closeDone)
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() 错误 = %v", err)
	}
	select {
	case <-openDone:
	case <-time.After(time.Second):
		t.Fatal("session open callback did not run")
	}
	mu.Lock()
	if opened.PID != os.Getpid() || opened.ProcessStartTime == 0 || opened.OwnerID == "" {
		t.Fatalf("opened session = %#v", opened)
	}
	if runtime.GOOS == "linux" && opened.WorkingDirectory == "" {
		t.Fatalf("Linux session should include working directory: %#v", opened)
	}
	mu.Unlock()
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() 错误 = %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("session close callback did not run")
	}
	mu.Lock()
	defer mu.Unlock()
	if closed.ID != opened.ID || closed.PID != opened.PID || closed.OwnerID != opened.OwnerID {
		t.Fatalf("closed session = %#v, opened = %#v", closed, opened)
	}
}

func TestServerSessionClosedProvidesOwnerForRuntimeLifecycle(t *testing.T) {
	t.Parallel()

	closed := make(chan Session, 1)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionClosed: func(session Session) {
			closed <- session
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	sessionID := client.SessionID()
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case session := <-closed:
		if session.ID != sessionID || session.OwnerID == "" {
			t.Fatalf("SessionClosed() = %#v，期望包含主体的已关闭会话", session)
		}
	case <-time.After(time.Second):
		t.Fatal("SessionClosed() did not provide a lifecycle callback")
	}
}

func TestServerNotifiesSessionClosedOnlyAfterLastCapabilityForOwner(t *testing.T) {
	t.Parallel()

	closed := make(chan Session, 2)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionClosed: func(session Session) {
			closed <- session
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	first, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(first) error = %v", err)
	}
	defer first.Close(context.Background())
	second, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(second) error = %v", err)
	}
	defer second.Close(context.Background())

	if err := first.Close(context.Background()); err != nil {
		t.Fatalf("first.Close() error = %v", err)
	}
	select {
	case session := <-closed:
		t.Fatalf("第一个 capability 关闭过早触发主体清理：%#v", session)
	default:
	}

	if err := second.Close(context.Background()); err != nil {
		t.Fatalf("second.Close() error = %v", err)
	}
	select {
	case session := <-closed:
		if session.OwnerID == "" {
			t.Fatalf("最后一个 capability 的关闭回调未携带 OwnerID：%#v", session)
		}
	case <-time.After(time.Second):
		t.Fatal("最后一个 capability 关闭后未触发主体清理")
	}
	select {
	case session := <-closed:
		t.Fatalf("同一主体关闭回调重复：%#v", session)
	default:
	}
}

func TestServerExpiresMultipleCapabilitiesWithOneOwnerCleanup(t *testing.T) {
	t.Parallel()

	closed := make(chan Session, 2)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionTTL: time.Millisecond,
		SessionClosed: func(session Session) {
			closed <- session
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	first, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(first) error = %v", err)
	}
	defer first.Close(context.Background())
	second, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(second) error = %v", err)
	}
	defer second.Close(context.Background())

	server.mu.Lock()
	for id, session := range server.sessions {
		session.ProcessStartTime = 0
		session.lastActivity = time.Now().Add(-time.Hour)
		server.sessions[id] = session
	}
	server.mu.Unlock()

	if active := server.ActiveSessions(); active != 0 {
		t.Fatalf("ActiveSessions() = %d, want 0", active)
	}
	select {
	case session := <-closed:
		if session.OwnerID == "" {
			t.Fatalf("过期主体清理未携带 OwnerID：%#v", session)
		}
	case <-time.After(time.Second):
		t.Fatal("主体的最后一个过期 capability 未触发清理")
	}
	select {
	case session := <-closed:
		t.Fatalf("同一主体过期回调重复：%#v", session)
	default:
	}
}

func TestServerCloseNotifiesEachOwnerOnce(t *testing.T) {
	t.Parallel()

	closed := make(chan Session, 2)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionClosed: func(session Session) {
			closed <- session
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	first, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(first) error = %v", err)
	}
	defer first.Close(context.Background())
	second, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect(second) error = %v", err)
	}
	defer second.Close(context.Background())

	if err := server.Close(); err != nil {
		t.Fatalf("Server.Close() error = %v", err)
	}
	select {
	case session := <-closed:
		if session.OwnerID == "" {
			t.Fatalf("Server.Close() 主体清理未携带 OwnerID：%#v", session)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close() 未触发主体清理")
	}
	select {
	case session := <-closed:
		t.Fatalf("Server.Close() 对同一主体重复回调：%#v", session)
	default:
	}
}

func TestServerRejectsMissingOrInvalidCapability(t *testing.T) {
	t.Parallel()

	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())
	client.token = "not-the-issued-capability"
	var result string
	if err := client.Call(context.Background(), "echo", nil, &result); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Call() error = %v, want ErrUnauthorized", err)
	}
}

func TestServerSocketCloseRevokesSession(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := Connect(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if server.ActiveSessions() != 1 {
		t.Fatalf("ActiveSessions() = %d, want 1", server.ActiveSessions())
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if server.ActiveSessions() != 0 {
		t.Fatalf("ActiveSessions() = %d, want 0", server.ActiveSessions())
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Server.Close() error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket remains after close: %v", err)
		}
	}
}

func TestServerRetainsIdleCapabilityWhileOwnerProcessIsAlive(t *testing.T) {
	t.Parallel()

	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionTTL: time.Millisecond,
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	server.mu.Lock()
	session := server.sessions[client.sessionID]
	session.lastActivity = time.Now().Add(-time.Hour)
	server.sessions[client.sessionID] = session
	server.mu.Unlock()

	if active := server.ActiveSessions(); active != 1 {
		t.Fatalf("ActiveSessions() = %d, want 1 for the live owner process", active)
	}
}

func TestServerMonitorClearsDeadOwnerWithoutStatusPoll(t *testing.T) {
	t.Parallel()

	closed := make(chan Session, 1)
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionTTL: time.Millisecond,
		SessionClosed: func(session Session) {
			closed <- session
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	server.mu.Lock()
	session := server.sessions[client.sessionID]
	session.ProcessStartTime = 0
	session.lastActivity = time.Now().Add(-time.Hour)
	server.sessions[client.sessionID] = session
	server.mu.Unlock()
	select {
	case session := <-closed:
		if session.OwnerID == "" {
			t.Fatalf("monitor SessionClosed() = %#v", session)
		}
	case <-time.After(time.Second):
		t.Fatal("monitor did not clear a dead bridge owner")
	}
}

func TestServerStartIsRejectedWhileCloseIsInProgress(t *testing.T) {
	t.Parallel()

	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
		SessionClosed: func(Session) {
			close(closeEntered)
			<-releaseClose
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case <-closeEntered:
	case <-time.After(time.Second):
		t.Fatal("Close() 未进入会话关闭回调")
	}
	if err := server.Start(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("关闭期间 Start() error = %v，期望 ErrInvalidRequest", err)
	}
	close(releaseClose)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestServerRejectsIncompatibleProtocolVersion(t *testing.T) {
	t.Parallel()

	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler:    HandlerFunc(func(context.Context, Session, string, json.RawMessage) (any, error) { return "ok", nil }),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	if _, err := roundTrip(context.Background(), server.SocketPath(), request{Version: ProtocolVersion + 1, Operation: "open"}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("roundTrip() error = %v, want ErrVersionMismatch", err)
	}
}

func TestClientContextCancellationCancelsDaemonHandler(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{})
	handlerCancelled := make(chan struct{})
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		Handler: HandlerFunc(func(ctx context.Context, _ Session, _ string, _ json.RawMessage) (any, error) {
			close(handlerStarted)
			<-ctx.Done()
			close(handlerCancelled)
			return nil, ctx.Err()
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	client, err := Connect(context.Background(), server.SocketPath())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Call(ctx, "wait", nil, &struct{}{}) }()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("daemon handler did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Call() error = %v，期望 context.Canceled", err)
	}
	select {
	case <-handlerCancelled:
	case <-time.After(time.Second):
		t.Fatal("daemon handler was not cancelled after client disconnect")
	}
}
