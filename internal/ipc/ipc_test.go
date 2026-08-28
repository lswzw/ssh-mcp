package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewTokenProducesDistinctURLSafeTokens(t *testing.T) {
	first, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	second, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if len(first) < 40 || first == second {
		t.Fatalf("unexpected tokens: %q, %q", first, second)
	}
}

func TestCategorizedControlErrorsRoundTripWithoutLeakingCause(t *testing.T) {
	t.Parallel()

	const secret = "remote failure contains candidate-password"
	cases := []struct {
		name     string
		category error
		code     string
	}{
		{name: "locked", category: ErrLocked, code: "locked"},
		{name: "not dispatched", category: ErrCandidateNotDispatched, code: "candidate_not_dispatched"},
		{name: "audit write", category: ErrCandidateAuditWriteFailed, code: "candidate_audit_write_failed"},
		{name: "confirmation", category: ErrConfirmationRequired, code: "confirmation_required"},
		{name: "connection", category: ErrCandidateConnectionFailed, code: "candidate_connection_failed"},
		{name: "authentication", category: ErrCandidateAuthenticationFailed, code: "candidate_authentication_failed"},
		{name: "TLS", category: ErrCandidateTLSFailed, code: "candidate_tls_failed"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := responseError(Categorize(errors.New(secret), test.category))
			if response.Code != test.code {
				t.Fatalf("response code = %q, want %q", response.Code, test.code)
			}
			if strings.Contains(response.Message, secret) {
				t.Fatalf("response leaked cause: %#v", response)
			}
			err := errorFromResponse(response)
			if !errors.Is(err, test.category) {
				t.Fatalf("errorFromResponse(%#v) = %v, want %v", response, err, test.category)
			}
		})
	}
}

func TestServerRoundTripCleansUp(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	server := NewServer(ServerOptions{
		SocketPath: socketPath,
		Token:      "test-token",
		Handler: HandlerFunc(func(_ context.Context, method string, params json.RawMessage) (any, error) {
			if method != "echo" {
				return nil, ErrMethodNotFound
			}
			var value string
			if err := json.Unmarshal(params, &value); err != nil {
				return nil, err
			}
			return value + "-reply", nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	var result string
	err := NewClient(socketPath, "test-token").Call(context.Background(), "echo", "request", &result)
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if result != "request-reply" {
		t.Fatalf("result = %q, want request-reply", result)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket still exists or could not stat it: %v", err)
		}
	}
}

func TestServerRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	server := NewServer(ServerOptions{
		SocketPath: socketPath,
		Token:      "correct-token",
		Handler: HandlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
			return "ok", nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	for _, token := range []string{"", "wrong-token"} {
		t.Run("token="+token, func(t *testing.T) {
			var result string
			err := NewClient(socketPath, token).Call(context.Background(), "anything", nil, &result)
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("token %q error = %v, want ErrUnauthorized", token, err)
			}
		})
	}
}

func TestServerReplacesAndDisablesCapabilityToken(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	server := NewServer(ServerOptions{
		SocketPath: socketPath,
		Token:      "first-token",
		Handler: HandlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
			return "ok", nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	call := func(token string) error {
		var result string
		return NewClient(socketPath, token).Call(context.Background(), "status", nil, &result)
	}
	if err := call("first-token"); err != nil {
		t.Fatalf("first token call error = %v", err)
	}
	if err := server.SetToken("second-token"); err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}
	for _, token := range []string{"", "first-token"} {
		if err := call(token); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("replaced token %q error = %v, want ErrUnauthorized", token, err)
		}
	}
	if err := call("second-token"); err != nil {
		t.Fatalf("second token call error = %v", err)
	}

	server.DisableToken()
	if err := call("second-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled token error = %v, want ErrUnauthorized", err)
	}
	if err := server.SetToken(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SetToken(empty) error = %v, want ErrInvalidRequest", err)
	}
}

func TestServerAcceptsSameUserRequestsWithoutCapabilityToken(t *testing.T) {
	t.Parallel()

	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "control.sock"),
		Handler: HandlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
			return "ok", nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()
	var result string
	if err := NewClient(server.socketPath, "").Call(context.Background(), "status", nil, &result); err != nil {
		t.Fatalf("same-user Call() error = %v", err)
	}
	if result != "ok" {
		t.Fatalf("result = %q", result)
	}
}

func TestClientCancellationCancelsServerHandler(t *testing.T) {
	t.Parallel()

	handlerStarted := make(chan struct{})
	handlerCancelled := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "control.sock"),
		Handler: HandlerFunc(func(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
			close(handlerStarted)
			select {
			case <-ctx.Done():
				close(handlerCancelled)
				return nil, ctx.Err()
			case <-releaseHandler:
				return "released", nil
			}
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动 IPC 服务失败：%v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callDone := make(chan error, 1)
	go func() {
		callDone <- NewClient(server.socketPath, "").Call(ctx, "wait", nil, &struct{}{})
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("IPC handler 未启动")
	}
	cancel()
	select {
	case <-handlerCancelled:
	case <-time.After(time.Second):
		close(releaseHandler)
		<-callDone
		t.Fatal("客户端取消后 IPC handler 未取消")
	}
	select {
	case err := <-callDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消后的 IPC 调用错误 = %v，期望 context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("取消后的 IPC 调用未返回")
	}
}
