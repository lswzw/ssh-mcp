package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const runAsMCPServer = "SSH_MCP_RUN_AS_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(runAsMCPServer) == "1" {
		main()
		return
	}

	os.Exit(m.Run())
}

func TestStdioMCPInitialization(t *testing.T) {
	ctx := context.Background()
	command := exec.Command(os.Args[0], "serve", "-test.run=TestStdioMCPInitialization")
	command.Env = append(os.Environ(), runAsMCPServer+"=1")

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test-version"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	serverInfo := session.InitializeResult().ServerInfo
	if serverInfo.Name != "ssh-mcp" {
		t.Errorf("server name = %q, want %q", serverInfo.Name, "ssh-mcp")
	}
	if serverInfo.Version != "dev" {
		t.Errorf("server version = %q, want %q", serverInfo.Version, "dev")
	}
}

func TestSelectStartupModeSeparatesManageAndMCP(t *testing.T) {
	testCases := []struct {
		name        string
		arguments   []string
		interactive bool
		want        startupMode
		wantErr     error
	}{
		{name: "explicit serve", arguments: []string{"serve"}, interactive: true, want: startupServer},
		{name: "explicit manage", arguments: []string{"manage"}, interactive: true, want: startupManage},
		{name: "interactive default", interactive: true, want: startupManage},
		{name: "noninteractive default", interactive: false, want: startupServer},
		{name: "internal tui child", arguments: []string{"tui"}, want: startupTUI},
		{name: "manage needs terminal", arguments: []string{"manage"}, wantErr: ErrManageRequiresTTY},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := selectStartupMode(testCase.arguments, testCase.interactive)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("selectStartupMode() error = %v, want %v", err, testCase.wantErr)
			}
			if err == nil && got != testCase.want {
				t.Fatalf("selectStartupMode() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestIsForceStopConfirmationAcceptsPlatformLineEndingsOnly(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input string
		want  bool
	}{
		{name: "unix line ending", input: "yes\n", want: true},
		{name: "windows line ending", input: "yes\r\n", want: true},
		{name: "missing newline", input: "yes", want: true},
		{name: "different case", input: "YES\r\n", want: false},
		{name: "leading whitespace", input: " yes\n", want: false},
		{name: "trailing whitespace", input: "yes \n", want: false},
		{name: "extra content", input: "yes\r\nno", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isForceStopConfirmation(test.input); got != test.want {
				t.Errorf("isForceStopConfirmation(%q) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}
