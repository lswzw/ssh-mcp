//go:build windows

package unixtransport

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPipeNameIsDeterministicAndDoesNotExposeEndpoint(t *testing.T) {
	endpoint := `C:\Users\alice\AppData\Local\ssh-mcp\control.sock`
	first := pipeName(endpoint)
	if first != pipeName(endpoint) {
		t.Fatal("pipe name changed for the same endpoint")
	}
	if len(first) <= len(`\\.\pipe\ssh-mcp-`) || first == endpoint {
		t.Fatalf("pipe name = %q", first)
	}
}

func TestDialLocalHonorsAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	connection, err := dialLocal(ctx, filepath.Join(t.TempDir(), "control.sock"))
	if connection != nil {
		_ = connection.Close()
		t.Fatal("canceled dial unexpectedly returned a connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial error = %v, want context.Canceled", err)
	}
}

func TestDialLocalReturnsWhenNamedPipeIsMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	connection, err := dialLocal(ctx, filepath.Join(t.TempDir(), "missing-control.sock"))
	if connection != nil {
		_ = connection.Close()
		t.Fatal("missing named pipe unexpectedly returned a connection")
	}
	if err == nil {
		t.Fatal("missing named pipe unexpectedly returned nil error")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing named pipe waited for context deadline: %v", err)
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("missing named pipe error = %v, want ERROR_FILE_NOT_FOUND", err)
	}
}

func TestPrepareLocalEndpointRejectsAnyOccupiedPath(t *testing.T) {
	for _, create := range []struct {
		name string
		fn   func(string) error
	}{
		{
			name: "regular file",
			fn: func(path string) error {
				return os.WriteFile(path, []byte("occupied"), 0o600)
			},
		},
		{
			name: "directory",
			fn:   func(path string) error { return os.Mkdir(path, 0o700) },
		},
	} {
		t.Run(create.name, func(t *testing.T) {
			endpoint := filepath.Join(t.TempDir(), "control.sock")
			if err := create.fn(endpoint); err != nil {
				t.Fatalf("create occupied endpoint: %v", err)
			}
			if err := prepareLocalEndpoint(endpoint); err == nil {
				t.Fatal("occupied endpoint was accepted")
			}
		})
	}
}

func TestServerStartRejectsExistingNamedPipe(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "control.sock")
	options := ServerOptions{
		SocketPath: endpoint,
		Handler: func(Request) json.RawMessage {
			return json.RawMessage(`{}`)
		},
		EncodeFailure: func(Failure) json.RawMessage {
			return json.RawMessage(`{}`)
		},
	}
	first := NewServer(options)
	if err := first.Start(); err != nil {
		t.Fatalf("start first named-pipe server: %v", err)
	}
	defer first.Close()

	second := NewServer(options)
	if err := second.Start(); err == nil {
		_ = second.Close()
		t.Fatal("second named-pipe server unexpectedly started")
	}
}

func TestAcceptLoopStopsAfterNonTemporaryError(t *testing.T) {
	listener := &failingListener{}
	server := &Server{}
	done := make(chan struct{})
	go func() {
		server.acceptLoop(listener)
		close(done)
	}()
	<-done
	if got := listener.calls.Load(); got != 1 {
		t.Fatalf("Accept calls = %d, want 1", got)
	}
}

func TestAcceptLoopRetriesTransientPipeDisconnect(t *testing.T) {
	listener := &transientDisconnectListener{}
	server := &Server{}
	done := make(chan struct{})
	go func() {
		server.acceptLoop(listener)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not stop after listener close")
	}
	if got := listener.calls.Load(); got != 2 {
		t.Fatalf("Accept calls = %d, want 2", got)
	}
}

func TestPipeAcceptErrorMarksClientDisconnectTemporary(t *testing.T) {
	err := pipeAcceptError(windows.ERROR_NO_DATA)
	var temporary interface{ Temporary() bool }
	if !errors.As(err, &temporary) || !temporary.Temporary() {
		t.Fatalf("disconnect error = %v, want temporary error", err)
	}
	if !errors.Is(err, windows.ERROR_NO_DATA) {
		t.Fatalf("disconnect error = %v, want ERROR_NO_DATA", err)
	}
}

func TestFinishAcceptReplenishesPendingPipeBeforeReturning(t *testing.T) {
	const (
		accepted    windows.Handle = 41
		replacement windows.Handle = 42
	)
	listener := &pipeListener{current: accepted, currentToken: 7}
	var createCalls atomic.Int32
	owned, closed, nextErr := listener.finishAccept(accepted, 7, nil, func() error {
		createCalls.Add(1)
		listener.current = replacement
		return nil
	})
	if !owned || closed || nextErr != nil {
		t.Fatalf("finishAccept() = (owned=%t, closed=%t, err=%v), want owned and open", owned, closed, nextErr)
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("replacement instance creation calls = %d, want 1", got)
	}
	if listener.current != replacement {
		t.Fatalf("pending handle = %d, want replacement %d", listener.current, replacement)
	}
}

func TestFinishAcceptDoesNotRecreateAfterListenerClose(t *testing.T) {
	const accepted windows.Handle = 41
	// Close atomically clears current before releasing the mutex. This is the
	// state observed by a blocked Accept after Close has taken handle ownership.
	listener := &pipeListener{closed: true}
	var createCalls atomic.Int32
	owned, closed, nextErr := listener.finishAccept(accepted, 7, windows.ERROR_OPERATION_ABORTED, func() error {
		createCalls.Add(1)
		return nil
	})
	if owned || !closed || nextErr != nil {
		t.Fatalf("finishAccept() = (owned=%t, closed=%t, err=%v), want not-owned/closed", owned, closed, nextErr)
	}
	if got := createCalls.Load(); got != 0 {
		t.Fatalf("replacement instance creation calls = %d, want 0", got)
	}
}

func TestFinishAcceptReplenishesAfterTransientDisconnect(t *testing.T) {
	const (
		accepted    windows.Handle = 41
		replacement windows.Handle = 42
	)
	listener := &pipeListener{current: accepted, currentToken: 7}
	var createCalls atomic.Int32
	owned, closed, nextErr := listener.finishAccept(accepted, 7, windows.ERROR_NO_DATA, func() error {
		createCalls.Add(1)
		listener.current = replacement
		return nil
	})
	if !owned || closed || nextErr != nil {
		t.Fatalf("finishAccept() = (owned=%t, closed=%t, err=%v), want owned and open", owned, closed, nextErr)
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("replacement instance creation calls = %d, want 1", got)
	}
	if listener.current != replacement {
		t.Fatalf("pending handle = %d, want replacement %d", listener.current, replacement)
	}
}

func TestFinishAcceptIgnoresReusedHandleWithDifferentGeneration(t *testing.T) {
	const accepted windows.Handle = 41
	listener := &pipeListener{current: accepted, currentToken: 9}
	var createCalls atomic.Int32
	owned, closed, nextErr := listener.finishAccept(accepted, 7, nil, func() error {
		createCalls.Add(1)
		return nil
	})
	if owned || closed || nextErr != nil {
		t.Fatalf("finishAccept() = (owned=%t, closed=%t, err=%v), want not-owned/ open", owned, closed, nextErr)
	}
	if got := createCalls.Load(); got != 0 {
		t.Fatalf("replacement instance creation calls = %d, want 0", got)
	}
	if listener.current != accepted || listener.currentToken != 9 {
		t.Fatalf("current instance changed for stale Accept: handle=%d token=%d", listener.current, listener.currentToken)
	}
}

type failingListener struct {
	calls atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	return nil, errors.New("permanent listener failure")
}

func (*failingListener) Close() error   { return nil }
func (*failingListener) Addr() net.Addr { return pipeAddr("failure") }

type transientDisconnectListener struct {
	calls atomic.Int32
}

func (l *transientDisconnectListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, pipeAcceptError(windows.ERROR_NO_DATA)
	}
	return nil, net.ErrClosed
}

func (*transientDisconnectListener) Close() error   { return nil }
func (*transientDisconnectListener) Addr() net.Addr { return pipeAddr("transient") }
