//go:build !windows

package unixtransport_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/ipc"
)

const oversizedFramePayloadSize = 1 << 20

type adapterContract struct {
	name                 string
	new                  func(string, int, *atomic.Int32) (func() error, func() error, func(context.Context) error)
	rawRequest           func() any
	oversizedFrame       func() []byte
	rawHandlerCallsAfter int32
}

func TestAdaptersKeepUnixSocketLifecycle(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "private", "local.sock")
			var calls atomic.Int32
			startServer, closeServer, call := contract.new(socketPath, os.Getuid(), &calls)
			if err := startServer(); err != nil {
				t.Fatalf("启动服务失败：%v", err)
			}
			defer closeServer()

			if err := call(context.Background()); err != nil {
				t.Fatalf("正常调用失败：%v", err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("正常调用的 handler 次数 = %d，期望 1", got)
			}
			if err := closeServer(); err != nil {
				t.Fatalf("关闭服务失败：%v", err)
			}
			if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("关闭后 socket 仍存在或无法读取：%v", err)
			}
		})
	}
}

func TestAdaptersRejectNonSocketPath(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "local.sock")
			if err := os.WriteFile(socketPath, []byte("保留内容"), 0o600); err != nil {
				t.Fatalf("创建普通文件失败：%v", err)
			}
			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(socketPath, os.Getuid(), &calls)
			if err := startServer(); err == nil {
				t.Fatal("普通文件路径意外被接受为 socket")
			}
			if err := closeServer(); err != nil {
				t.Fatalf("关闭失败启动的服务失败：%v", err)
			}
			content, err := os.ReadFile(socketPath)
			if err != nil {
				t.Fatalf("读取保留普通文件失败：%v", err)
			}
			if got := string(content); got != "保留内容" {
				t.Fatalf("普通文件内容 = %q，期望保留内容", got)
			}
		})
	}
}

func TestAdaptersRejectSymbolicLinkSocketDirectory(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			root := t.TempDir()
			targetDirectory := filepath.Join(root, "target")
			if err := os.Mkdir(targetDirectory, 0o700); err != nil {
				t.Fatalf("创建目标目录失败：%v", err)
			}
			linkedDirectory := filepath.Join(root, "linked")
			if err := os.Symlink(targetDirectory, linkedDirectory); err != nil {
				t.Fatalf("创建符号链接目录失败：%v", err)
			}

			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(filepath.Join(linkedDirectory, "local.sock"), os.Getuid(), &calls)
			if err := startServer(); err == nil {
				t.Fatal("符号链接目录意外被接受为 socket 目录")
			}
			if err := closeServer(); err != nil {
				t.Fatalf("关闭失败启动的服务失败：%v", err)
			}
			if _, err := os.Lstat(filepath.Join(targetDirectory, "local.sock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("符号链接目标目录出现 socket 或无法读取：%v", err)
			}
		})
	}
}

func TestAdaptersRejectForeignUnixPeer(t *testing.T) {
	foreignUID := os.Getuid() + 1
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "local.sock")
			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(socketPath, foreignUID, &calls)
			if err := startServer(); err != nil {
				t.Fatalf("启动服务失败：%v", err)
			}
			defer closeServer()
			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatalf("连接服务失败：%v", err)
			}
			defer connection.Close()
			var response struct {
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				t.Fatalf("读取异 UID 响应失败：%v", err)
			}
			if response.Error == nil || response.Error.Code != "unauthorized" {
				t.Fatalf("异 UID 响应错误码 = %#v，期望 unauthorized", response.Error)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("异 UID 请求的 handler 次数 = %d，期望 0", got)
			}
		})
	}
}

func TestAdaptersCloseConnectionAfterOneRawRequest(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "local.sock")
			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(socketPath, os.Getuid(), &calls)
			if err := startServer(); err != nil {
				t.Fatalf("启动服务失败：%v", err)
			}
			defer closeServer()

			connection, err := net.Dial("unix", socketPath)
			if err != nil {
				t.Fatalf("连接服务失败：%v", err)
			}
			defer connection.Close()
			if err := json.NewEncoder(connection).Encode(contract.rawRequest()); err != nil {
				t.Fatalf("写入原始请求失败：%v", err)
			}
			var response struct {
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				t.Fatalf("读取原始响应失败：%v", err)
			}
			if response.Error != nil {
				t.Fatalf("原始请求响应错误码 = %q", response.Error.Code)
			}
			if got := calls.Load(); got != contract.rawHandlerCallsAfter {
				t.Fatalf("原始请求的 handler 次数 = %d，期望 %d", got, contract.rawHandlerCallsAfter)
			}
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("设置读取截止时间失败：%v", err)
			}
			var extra json.RawMessage
			err = json.NewDecoder(connection).Decode(&extra)
			if !errors.Is(err, io.EOF) {
				t.Fatalf("单次响应后连接读取错误 = %v，期望 io.EOF", err)
			}
		})
	}
}

func TestAdaptersRejectMalformedFrameBeforeHandler(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "local.sock")
			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(socketPath, os.Getuid(), &calls)
			if err := startServer(); err != nil {
				t.Fatalf("启动服务失败：%v", err)
			}
			defer closeServer()

			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatalf("连接服务失败：%v", err)
			}
			defer connection.Close()
			if _, err := connection.Write([]byte(`{"`)); err != nil {
				t.Fatalf("写入畸形帧失败：%v", err)
			}
			if err := connection.CloseWrite(); err != nil {
				t.Fatalf("关闭请求写入端失败：%v", err)
			}
			var response struct {
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				t.Fatalf("读取畸形帧响应失败：%v", err)
			}
			if response.Error == nil || response.Error.Code != "invalid_request" {
				t.Fatalf("畸形帧错误码 = %#v，期望 invalid_request", response.Error)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("畸形帧的 handler 次数 = %d，期望 0", got)
			}
		})
	}
}

func TestAdaptersRejectOversizedFrameBeforeHandler(t *testing.T) {
	for _, contract := range adapterContracts() {
		t.Run(contract.name, func(t *testing.T) {
			frame := contract.oversizedFrame()
			if len(frame) <= oversizedFramePayloadSize {
				t.Fatalf("超限帧长度 = %d，期望大于 %d", len(frame), oversizedFramePayloadSize)
			}
			socketPath := filepath.Join(t.TempDir(), "local.sock")
			var calls atomic.Int32
			startServer, closeServer, _ := contract.new(socketPath, os.Getuid(), &calls)
			if err := startServer(); err != nil {
				t.Fatalf("启动服务失败：%v", err)
			}
			defer closeServer()

			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatalf("连接服务失败：%v", err)
			}
			defer connection.Close()
			if _, err := connection.Write(frame); err != nil {
				t.Fatalf("写入超限帧失败：%v", err)
			}
			if err := connection.CloseWrite(); err != nil {
				t.Fatalf("关闭超限帧写入端失败：%v", err)
			}
			var response struct {
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				t.Fatalf("读取超限帧响应失败：%v", err)
			}
			if response.Error == nil || response.Error.Code != "invalid_request" {
				t.Fatalf("超限帧错误码 = %#v，期望 invalid_request", response.Error)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("超限帧的 handler 次数 = %d，期望 0", got)
			}
		})
	}
}

func adapterContracts() []adapterContract {
	return []adapterContract{
		{
			name: "bridge",
			new: func(socketPath string, uid int, calls *atomic.Int32) (func() error, func() error, func(context.Context) error) {
				server := bridge.NewServer(bridge.ServerOptions{
					SocketPath: socketPath,
					UID:        uid,
					Handler: bridge.HandlerFunc(func(context.Context, bridge.Session, string, json.RawMessage) (any, error) {
						calls.Add(1)
						return "ok", nil
					}),
				})
				return server.Start, server.Close, func(ctx context.Context) error {
					client, err := bridge.Connect(ctx, socketPath)
					if err != nil {
						return err
					}
					defer client.Close(context.Background())
					var result string
					if err := client.Call(ctx, "echo", nil, &result); err != nil {
						return err
					}
					if result != "ok" {
						return fmt.Errorf("bridge 结果 = %q", result)
					}
					return nil
				}
			},
			rawRequest: func() any {
				return map[string]any{"version": bridge.ProtocolVersion, "operation": "open"}
			},
			oversizedFrame: func() []byte {
				return []byte(`{"version":1,"operation":"open","payload":"` + strings.Repeat("x", oversizedFramePayloadSize) + `"}`)
			},
			rawHandlerCallsAfter: 0,
		},
		{
			name: "ipc",
			new: func(socketPath string, uid int, calls *atomic.Int32) (func() error, func() error, func(context.Context) error) {
				server := ipc.NewServer(ipc.ServerOptions{
					SocketPath: socketPath,
					UID:        uid,
					Handler: ipc.HandlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
						calls.Add(1)
						return "ok", nil
					}),
				})
				return server.Start, server.Close, func(ctx context.Context) error {
					var result string
					if err := ipc.NewClient(socketPath, "").Call(ctx, "echo", nil, &result); err != nil {
						return err
					}
					if result != "ok" {
						return fmt.Errorf("IPC 结果 = %q", result)
					}
					return nil
				}
			},
			rawRequest: func() any {
				return map[string]any{"method": "echo"}
			},
			oversizedFrame: func() []byte {
				return []byte(`{"method":"echo","params":"` + strings.Repeat("x", oversizedFramePayloadSize) + `"}`)
			},
			rawHandlerCallsAfter: 1,
		},
	}
}
