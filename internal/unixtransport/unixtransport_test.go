//go:build !windows

package unixtransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerHandlesOneRequestAndCleansUpSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "local.sock")
	var requests atomic.Int32
	server := NewServer(ServerOptions{
		SocketPath:  socketPath,
		ExpectedUID: os.Getuid(),
		Handler: func(request Request) json.RawMessage {
			requests.Add(1)
			return json.RawMessage(`{"result":"ok"}`)
		},
		EncodeFailure: func(Failure) json.RawMessage {
			return json.RawMessage(`{"error":"rejected"}`)
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动本地 Unix 传输服务失败：%v", err)
	}
	defer server.Close()

	connection, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("连接本地 Unix 传输服务失败：%v", err)
	}
	defer connection.Close()
	if err := Encode(connection, map[string]string{"method": "echo"}); err != nil {
		t.Fatalf("写入单次请求失败：%v", err)
	}
	var response map[string]string
	if err := Decode(connection, &response); err != nil {
		t.Fatalf("读取单次响应失败：%v", err)
	}
	if got := response["result"]; got != "ok" {
		t.Fatalf("响应结果 = %q，期望 ok", got)
	}
	if requests.Load() != 1 {
		t.Fatalf("处理请求次数 = %d，期望 1", requests.Load())
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("设置读取截止时间失败：%v", err)
	}
	var extra map[string]string
	err = Decode(connection, &extra)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("单次响应后连接读取错误 = %v，期望 io.EOF", err)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("关闭本地 Unix 传输服务失败：%v", err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("关闭后 socket 仍存在或无法读取：%v", err)
	}
}

func TestDecodeRejectsMessageExceedingLimit(t *testing.T) {
	payload := `{"payload":"` + strings.Repeat("x", MaxMessageSize) + `"}`
	var message json.RawMessage
	if err := Decode(strings.NewReader(payload), &message); err == nil {
		t.Fatal("超过 1 MiB 的消息意外被接受")
	}
}

func TestServerAllowsOnlyOneConcurrentStart(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "local.sock")
	server := NewServer(ServerOptions{
		SocketPath:  socketPath,
		ExpectedUID: os.Getuid(),
		Handler: func(Request) json.RawMessage {
			return json.RawMessage(`{}`)
		},
		EncodeFailure: func(Failure) json.RawMessage {
			return json.RawMessage(`{}`)
		},
	})
	defer server.Close()

	start := make(chan struct{})
	errorsByStart := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsByStart <- server.Start()
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByStart)

	succeeded := 0
	for err := range errorsByStart {
		if err == nil {
			succeeded++
			continue
		}
		if !errors.Is(err, ErrInvalidServer) {
			t.Fatalf("并发启动错误 = %v，期望 ErrInvalidServer", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("并发启动成功次数 = %d，期望 1", succeeded)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("读取唯一启动的 socket 失败：%v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("唯一启动后的路径不是 socket")
	}
}

func TestServerRejectsLiveSocketEndpoint(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "live.sock")
	newServer := func() *Server {
		return NewServer(ServerOptions{
			SocketPath:  socketPath,
			ExpectedUID: os.Getuid(),
			Handler: func(Request) json.RawMessage {
				return json.RawMessage(`{}`)
			},
			EncodeFailure: func(Failure) json.RawMessage {
				return json.RawMessage(`{}`)
			},
		})
	}
	first := newServer()
	if err := first.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	defer first.Close()

	second := newServer()
	defer second.Close()
	if err := second.Start(); err == nil {
		t.Fatal("second server unexpectedly replaced a live socket endpoint")
	}
}

func TestServerReleasesEndpointLockAfterClose(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "restart.sock")
	newServer := func() *Server {
		return NewServer(ServerOptions{
			SocketPath:  socketPath,
			ExpectedUID: os.Getuid(),
			Handler: func(Request) json.RawMessage {
				return json.RawMessage(`{}`)
			},
			EncodeFailure: func(Failure) json.RawMessage {
				return json.RawMessage(`{}`)
			},
		})
	}
	first := newServer()
	if err := first.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	second := newServer()
	if err := second.Start(); err != nil {
		t.Fatalf("second Start() after close error = %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}
