package sshtransport

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestDirectSSHIntegration(t *testing.T) {
	endpoint, ok := endpointFromEnvironment("SSH_MCP_TEST_SSH")
	if !ok {
		t.Skip("direct SSH integration environment is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fingerprint, err := ProbeHostKey(ctx, endpoint)
	if err != nil {
		t.Fatalf("ProbeHostKey() error = %v", err)
	}
	endpoint.Fingerprint = fingerprint
	client, err := Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()
	result, err := client.Execute(ctx, "printf ssh-mcp-direct", false, 1024)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.ExitStatus != 0 || result.Stdout != "ssh-mcp-direct" {
		t.Fatalf("direct result = %#v", result)
	}
}

func endpointFromEnvironment(prefix string) (Endpoint, bool) {
	host, portValue, username, password := os.Getenv(prefix+"_HOST"), os.Getenv(prefix+"_PORT"), os.Getenv(prefix+"_USERNAME"), os.Getenv(prefix+"_PASSWORD")
	if host == "" || portValue == "" || username == "" || password == "" {
		return Endpoint{}, false
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return Endpoint{}, false
	}
	return Endpoint{Host: host, Port: port, Username: username, Password: []byte(password)}, true
}
