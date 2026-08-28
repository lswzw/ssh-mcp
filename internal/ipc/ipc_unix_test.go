//go:build !windows

package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestServerRejectsForeignUser(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	server := NewServer(ServerOptions{
		SocketPath: socketPath,
		UID:        os.Getuid() + 1,
		Handler: HandlerFunc(func(context.Context, string, json.RawMessage) (any, error) {
			return "ok", nil
		}),
	})
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Close()

	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("连接异 UID Unix socket 失败：%v", err)
	}
	defer connection.Close()
	var response Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatalf("读取异 UID 响应失败：%v", err)
	}
	if response.Error == nil || response.Error.Code != "unauthorized" {
		t.Fatalf("异 UID 响应 = %#v，期望 unauthorized", response.Error)
	}
}
