package runner

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

func TestReadSSHFileReadsCanonicalPathThroughDedicatedReader(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	reader := &fakeSSHFileReader{result: sshtransport.FileReadResult{
		Content: "database_url=remote-secret-value", Encoding: sshtransport.FileEncodingUTF8,
		BytesRead: 32, FileSize: 32, EOF: true,
	}}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh, FileReader: reader,
		Database: deps.database, WorkSessions: deps.workSessions, Audit: deps.audit,
		OpenTUI: deps.OpenTUI, SessionID: "file-read-test",
	})

	result, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{
		Target: "192.0.2.10", Path: "/srv/app/config/application.env", Offset: 0, MaxBytes: 512,
	})
	if err != nil {
		t.Fatalf("ReadSSHFile() error = %v", err)
	}
	if result.Status != StatusCompleted || !result.RemoteExecuted || !result.UntrustedRemoteOutput || result.File == nil ||
		result.File.Content != "database_url=remote-secret-value" || result.File.Encoding != sshtransport.FileEncodingUTF8 ||
		result.File.Path != "/srv/app/config/application.env" || result.File.Offset != 0 {
		t.Fatalf("ReadSSHFile() = %#v", result)
	}
	if reader.calls != 1 || reader.path != "/srv/app/config/application.env" || reader.offset != 0 || reader.maxBytes != 512 || deps.ssh.calls != 0 {
		t.Fatalf("file reader = %#v, SSH executor = %#v", reader, deps.ssh)
	}
	if len(deps.audit.entries) != 2 || deps.audit.entries[0].Action != "ssh_file_read" ||
		deps.audit.entries[1].Action != "ssh_file_read" || deps.audit.entries[1].File.Path != "/srv/app/config/application.env" ||
		deps.audit.entries[1].File.Offset != 0 || deps.audit.entries[1].File.BytesRead == nil || *deps.audit.entries[1].File.BytesRead != 32 {
		t.Fatalf("audit entries = %#v", deps.audit.entries)
	}
	encoded, err := json.Marshal(deps.audit.entries)
	if err != nil {
		t.Fatalf("marshal audit entries: %v", err)
	}
	if strings.Contains(string(encoded), "remote-secret-value") || strings.Contains(string(encoded), "database_url") {
		t.Fatalf("audit contains remote file content: %s", encoded)
	}
}

func TestReadSSHFileRejectsDisabledTargetOrInvalidPathBeforeDispatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		disable     bool
		path        string
		failureKind string
	}{
		{name: "file operations disabled", disable: true, path: "/srv/app/config/application.env", failureKind: FailureKindFileOperationsDisabled},
		{name: "relative path", path: "srv/app/config/application.env", failureKind: FailureKindFileReadPathInvalid},
		{name: "path traversal", path: "/srv/app/config/../secret", failureKind: FailureKindFileReadPathInvalid},
		{name: "duplicate separator", path: "/srv/app/config//application.env", failureKind: FailureKindFileReadPathInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newFakeDependencies()
			deps.targets.sshTarget.AllowFileOperations = !tc.disable
			reader := &fakeSSHFileReader{}
			engine := New(Dependencies{
				Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh, FileReader: reader,
				Database: deps.database, WorkSessions: deps.workSessions, Audit: deps.audit,
				OpenTUI: deps.OpenTUI, SessionID: "file-read-test",
			})

			result, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{
				Target: "192.0.2.10", Path: tc.path, MaxBytes: 256,
			})
			if err != nil {
				t.Fatalf("ReadSSHFile() error = %v", err)
			}
			if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted || result.FailureKind != tc.failureKind || reader.calls != 0 || deps.ssh.calls != 0 {
				t.Fatalf("ReadSSHFile() = %#v, reader = %#v, SSH = %#v", result, reader, deps.ssh)
			}
			if len(deps.audit.entries) != 1 || deps.audit.entries[0].RemoteExecuted || deps.audit.entries[0].File.Path != tc.path {
				t.Fatalf("audit entries = %#v", deps.audit.entries)
			}
		})
	}
}

func TestReadSSHFileUsesIndependentDefaultAndHardByteLimit(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	reader := &fakeSSHFileReader{result: sshtransport.FileReadResult{Encoding: sshtransport.FileEncodingUTF8, EOF: true}}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh, FileReader: reader,
		Database: deps.database, WorkSessions: deps.workSessions, Audit: deps.audit,
		OpenTUI: deps.OpenTUI, SessionID: "file-read-test",
	})

	result, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{Target: "192.0.2.10", Path: "/srv/app/config.yaml"})
	if err != nil {
		t.Fatalf("default ReadSSHFile() error = %v", err)
	}
	if result.Status != StatusCompleted || reader.maxBytes != sshtransport.DefaultFileReadBytes {
		t.Fatalf("default ReadSSHFile() = %#v, reader = %#v", result, reader)
	}

	tooLarge, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{
		Target: "192.0.2.10", Path: "/srv/app/config.yaml", MaxBytes: sshtransport.MaxFileReadBytes + 1,
	})
	if err != nil {
		t.Fatalf("over-limit ReadSSHFile() error = %v", err)
	}
	if tooLarge.Status != StatusRejected || tooLarge.ExecutionOutcome != StatusNotDispatched || tooLarge.RemoteExecuted || reader.calls != 1 {
		t.Fatalf("over-limit ReadSSHFile() = %#v, reader = %#v", tooLarge, reader)
	}
}

func TestReadSSHFileKeepsPostDispatchCancellationOutcomeUnknown(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	reader := &fakeSSHFileReader{err: sshtransport.ErrFileReadOutcomeUnknown}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh, FileReader: reader,
		Database: deps.database, WorkSessions: deps.workSessions, Audit: deps.audit,
		OpenTUI: deps.OpenTUI, SessionID: "file-read-test",
	})

	result, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{Target: "192.0.2.10", Path: "/srv/app/config.yaml"})
	if err != nil {
		t.Fatalf("ReadSSHFile() error = %v", err)
	}
	if result.Status != StatusOutcomeUnknown || result.ExecutionOutcome != StatusOutcomeUnknown || !result.RemoteExecuted || reader.calls != 1 {
		t.Fatalf("ReadSSHFile() = %#v, reader = %#v", result, reader)
	}
	if len(deps.audit.entries) != 2 || !deps.audit.entries[1].RemoteExecuted || deps.audit.entries[1].Result.Status != StatusOutcomeUnknown {
		t.Fatalf("audit entries = %#v", deps.audit.entries)
	}
}

func TestReadSSHFileRejectsChangedTargetBeforeRemoteRead(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	reader := &fakeSSHFileReader{err: store.ErrTargetChanged}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh, FileReader: reader,
		Database: deps.database, WorkSessions: deps.workSessions, Audit: deps.audit,
		OpenTUI: deps.OpenTUI, SessionID: "file-read-test",
	})

	result, err := engine.ReadSSHFile(context.Background(), SSHFileReadRequest{Target: "192.0.2.10", Path: "/srv/app/config.yaml"})
	if err != nil {
		t.Fatalf("ReadSSHFile() error = %v", err)
	}
	if result.Status != StatusNotDispatched || result.RemoteExecuted || reader.calls != 1 {
		t.Fatalf("ReadSSHFile() = %#v, reader = %#v", result, reader)
	}
}

type fakeSSHFileReader struct {
	result   sshtransport.FileReadResult
	err      error
	calls    int
	path     string
	offset   int64
	maxBytes int
	timeout  time.Duration
}

func (r *fakeSSHFileReader) ReadFile(ctx context.Context, _ *store.Vault, _ store.SSHTarget, path string, offset int64, maxBytes int) (sshtransport.FileReadResult, error) {
	r.calls++
	r.path = path
	r.offset = offset
	r.maxBytes = maxBytes
	r.timeout = deadline(ctx)
	return r.result, r.err
}

var _ SSHFileReader = (*fakeSSHFileReader)(nil)

var _ = errors.Is
