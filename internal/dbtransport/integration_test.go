package dbtransport

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"ssh-mcp/internal/store"
)

func TestMySQLIntegration(t *testing.T) {
	endpoint := databaseEndpointFromEnvironment(t, "MYSQL", store.EngineMySQL)
	transport := NativeTransport{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	security, err := transport.Test(ctx, endpoint)
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if security != SecurityPlaintext {
		t.Fatalf("MySQL security = %q, want plaintext after TLS compatibility fallback", security)
	}
	if _, err := transport.ListDatabases(ctx, endpoint); err != nil {
		t.Fatalf("ListDatabases() error = %v", err)
	}
	result, err := transport.Query(ctx, endpoint, "SELECT 1", Limits{MaxRows: 1, MaxBytes: 64})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("query result = %#v", result)
	}
	assertReadOnlyQuery(t, transport, ctx, endpoint, "SELECT @@transaction_read_only", "1")
	assertExecutionBoundaries(t, transport, endpoint,
		"SELECT REPEAT('x', 128)", "SELECT SLEEP(1)", "SELECT * FROM ssh_mcp_missing_table")
}

func TestPostgresIntegration(t *testing.T) {
	endpoint := databaseEndpointFromEnvironment(t, "POSTGRES", store.EnginePostgreSQL)
	transport := NativeTransport{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := transport.Test(ctx, endpoint); err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if _, err := transport.ListDatabases(ctx, endpoint); err != nil {
		t.Fatalf("ListDatabases() error = %v", err)
	}
	result, err := transport.Query(ctx, endpoint, "SELECT 1", Limits{MaxRows: 1, MaxBytes: 64})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("query result = %#v", result)
	}
	assertReadOnlyQuery(t, transport, ctx, endpoint, "SHOW transaction_read_only", "on")
	assertExecutionBoundaries(t, transport, endpoint,
		"SELECT repeat('x', 128)", "SELECT pg_sleep(1)", "SELECT * FROM ssh_mcp_missing_table")
}

func assertReadOnlyQuery(t *testing.T, transport NativeTransport, ctx context.Context, endpoint Endpoint, statement, want string) {
	t.Helper()
	result, err := transport.Query(ctx, endpoint, statement, Limits{MaxRows: 1, MaxBytes: 64})
	if err != nil {
		t.Fatalf("read-only Query(%q) error = %v", statement, err)
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != want {
		t.Fatalf("read-only Query(%q) = %#v, want %q", statement, result, want)
	}
}

func assertExecutionBoundaries(t *testing.T, transport NativeTransport, endpoint Endpoint, oversizedQuery, slowQuery, failingQuery string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := transport.Query(ctx, endpoint, oversizedQuery, Limits{MaxRows: 1, MaxBytes: 16})
	if err != nil {
		t.Fatalf("byte-limited Query() error = %v", err)
	}
	if !result.BytesTruncated {
		t.Fatalf("byte-limited result = %#v", result)
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer timeoutCancel()
	if _, err := transport.Query(timeoutCtx, endpoint, slowQuery, Limits{MaxRows: 1, MaxBytes: 64}); err == nil {
		t.Fatal("slow query completed after context cancellation")
	}
	if _, err := transport.ExecuteStatements(ctx, endpoint, []string{"SELECT 1"}); err != nil {
		t.Fatalf("read-only statement batch error = %v", err)
	}
	if _, err := transport.ExecuteStatements(ctx, endpoint, []string{"SELECT 1", failingQuery}); err == nil {
		t.Fatal("failing statement batch unexpectedly succeeded")
	}
}

func databaseEndpointFromEnvironment(t *testing.T, prefix string, engine store.DatabaseEngine) Endpoint {
	t.Helper()
	host := os.Getenv("SSH_MCP_TEST_" + prefix + "_HOST")
	portText := os.Getenv("SSH_MCP_TEST_" + prefix + "_PORT")
	username := os.Getenv("SSH_MCP_TEST_" + prefix + "_USERNAME")
	password := os.Getenv("SSH_MCP_TEST_" + prefix + "_PASSWORD")
	if host == "" || portText == "" || username == "" || password == "" {
		t.Skip("database integration environment is not configured")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return Endpoint{
		Host: host, Port: port, Engine: engine, Database: os.Getenv("SSH_MCP_TEST_" + prefix + "_DATABASE"),
		Username: username, Password: []byte(password),
	}
}
