package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoggerWritesJSONLWithRedactedOperation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger := New(path)
	t.Cleanup(func() { _ = logger.Close() })
	err := logger.Record(context.Background(), Event{
		Time:           time.Date(2026, 7, 23, 10, 30, 0, 0, time.FixedZone("CST", 8*60*60)),
		OperationID:    "operation-123",
		Phase:          PhaseCompleted,
		RemoteExecuted: true,
		Actor:          Actor{User: "kub", PID: 1234, WorkingDirectory: "/home/kub/project", Source: "codex-mcp", BridgeSessionID: "bridge-123"},
		Target:         Target{Kind: "ssh", ID: "192.0.2.10"},
		Policy:         Policy{Version: "test", Decision: "allowed", Risk: ""},
		SSHCommand:     "MYSQL_ROOT_PASSWORD=super-secret docker compose up -d",
		Result:         Result{Status: "completed", ExitStatus: intPointer(0), DurationMS: int64Pointer(18)},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(contents), "super-secret") {
		t.Fatalf("audit log leaked credential: %s", contents)
	}
	var event Event
	if err := json.Unmarshal(contents, &event); err != nil {
		t.Fatalf("audit log is not JSONL: %v", err)
	}
	if event.Actor.User != "kub" || event.Target.ID != "192.0.2.10" || event.Result.Status != "completed" || !event.RemoteExecuted {
		t.Fatalf("event = %#v", event)
	}
	if !strings.Contains(event.SSHCommand, "[REDACTED]") {
		t.Fatalf("command was not redacted: %q", event.SSHCommand)
	}
}

func TestLoggerUsesBeijingTimeWhenEventTimeIsOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := NewWithOptions(path, Options{Now: func() time.Time {
		return time.Date(2026, time.July, 23, 2, 30, 0, 0, time.UTC)
	}})
	t.Cleanup(func() { _ = logger.Close() })
	if err := logger.Record(context.Background(), Event{Phase: PhaseDecision, Target: Target{Kind: "ssh", ID: "192.0.2.10"}}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(contents), `"time":"2026-07-23T10:30:00+08:00"`) {
		t.Fatalf("audit time = %s", contents)
	}
}

func TestLoggerRedactsAllSQLLiteralsAndNeverRecordsOutput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger := New(path)
	t.Cleanup(func() { _ = logger.Close() })
	err := logger.Record(context.Background(), Event{
		Time:        time.Now(),
		OperationID: "operation-sql",
		Phase:       PhaseCompleted,
		Target:      Target{Kind: "database", ID: "192.0.2.20:5432"},
		SQL:         "UPDATE users SET name = 'Wang', api_token = 's3cret' WHERE id = 42; -- customer note",
		Result:      Result{Status: "completed", AffectedRows: int64Pointer(1), OutputTruncated: true},
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var event Event
	if err := json.Unmarshal(contents, &event); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	for _, forbidden := range []string{"Wang", "s3cret", "42", "customer note"} {
		if strings.Contains(event.SQL, forbidden) {
			t.Fatalf("audit log leaked SQL literal %q: %s", forbidden, event.SQL)
		}
	}
	if !strings.Contains(event.SQL, "UPDATE users SET") || strings.Count(event.SQL, "[REDACTED]") < 3 {
		t.Fatalf("SQL redaction = %q", event.SQL)
	}
}

func TestLoggerRedactsSQLCommentsAndDoubleQuotedValues(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger := New(path)
	t.Cleanup(func() { _ = logger.Close() })
	if err := logger.Record(context.Background(), Event{
		Phase: PhaseDecision, Target: Target{Kind: "database", ID: "192.0.2.20:3306"},
		SQL: "INSERT INTO notes(value) VALUES (\"mysql-secret\"); # hash-secret\n/* block-secret */ SELECT 'quoted-secret'",
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, secret := range []string{"mysql-secret", "hash-secret", "block-secret", "quoted-secret"} {
		if strings.Contains(string(contents), secret) {
			t.Fatalf("audit log leaked %q: %s", secret, contents)
		}
	}
}

func TestLoggerRotatesArchives(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger := NewWithOptions(path, Options{MaxBytes: 300, Archives: 2})
	t.Cleanup(func() { _ = logger.Close() })
	for index := 0; index < 5; index++ {
		err := logger.Record(context.Background(), Event{
			Time: time.Now(), Phase: PhaseCompleted, Target: Target{Kind: "ssh", ID: "192.0.2.10"},
			SSHCommand: strings.Repeat("x", 128), Result: Result{Status: "completed"},
		})
		if err != nil {
			t.Fatalf("Record(%d) error = %v", index, err)
		}
	}

	for _, name := range []string{"audit.log", "audit.log.1", "audit.log.2"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); err != nil {
			t.Fatalf("%s stat error = %v", name, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected third archive error = %v", err)
	}
}

func TestLoggerSerializesConcurrentAppends(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger := New(path)
	t.Cleanup(func() { _ = logger.Close() })
	var group sync.WaitGroup
	for index := 0; index < 24; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			err := logger.Record(context.Background(), Event{
				Time: time.Now(), Phase: PhaseDecision, OperationID: "operation", Target: Target{Kind: "ssh", ID: "192.0.2.10"},
				Result: Result{Status: "completed"},
			})
			if err != nil {
				t.Errorf("Record(%d) error = %v", index, err)
			}
		}(index)
	}
	group.Wait()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 24 {
		t.Fatalf("log line count = %d, want 24", len(lines))
	}
	for _, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid concurrent JSON event %q: %v", line, err)
		}
	}
}

func TestLoggerReturnsWhenPreviousWriteBlocksPastContextDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := New(path)
	t.Cleanup(func() { _ = logger.Close() })
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	defer func() {
		select {
		case <-releaseWrite:
		default:
			close(releaseWrite)
		}
	}()
	logger.appendEncoded = func(ctx context.Context, _ []byte) error {
		select {
		case <-writeStarted:
		default:
			close(writeStarted)
		}
		<-releaseWrite
		return ctx.Err()
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- logger.Record(context.Background(), Event{Phase: PhaseDecision, Target: Target{Kind: "ssh", ID: "192.0.2.10"}})
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("audit writer did not begin the first write")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := logger.Record(ctx, Event{Phase: PhaseDecision, Target: Target{Kind: "ssh", ID: "192.0.2.11"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Record() error = %v, want context deadline", err)
	}

	close(releaseWrite)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Record() error = %v", err)
	}
}

func TestLoggerCloseStopsIdleWriterAndRejectsNewRecords(t *testing.T) {
	logger := New(filepath.Join(t.TempDir(), "audit.log"))
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-logger.stopped:
	case <-time.After(time.Second):
		t.Fatal("审计写入器未在关闭后退出")
	}
	if err := logger.Record(context.Background(), Event{Phase: PhaseDecision, Target: Target{Kind: "ssh", ID: "192.0.2.10"}}); !errors.Is(err, errLoggerClosed) {
		t.Fatalf("关闭后的 Record() error = %v, want logger closed", err)
	}
}

func intPointer(value int) *int { return &value }

func int64Pointer(value int64) *int64 { return &value }
