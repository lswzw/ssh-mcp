package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

func TestDeploySSHBinaryUsesDirectSourceDestinationAndStartAction(t *testing.T) {
	t.Parallel()

	payload := []byte("direct deployment payload")
	sourcePath := writeDeploymentSource(t, payload)
	checksum := digest(payload)
	deps := newFakeDependencies()
	deployer := &fakeSSHBinaryDeployer{result: sshtransport.BinaryDeploymentResult{
		RemotePath:    "/srv/app/service",
		BackupPath:    "/srv/app/.ssh-mcp-backup-1",
		BytesUploaded: int64(len(payload)),
		SHA256:        checksum,
		Activated:     true,
	}}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI, SessionID: "deployment-test",
	})

	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: sourcePath, RemotePath: "/srv/app/service",
		StartAction: "systemctl restart app.service",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusCompleted || result.ExecutionOutcome != StatusCompleted ||
		result.Deployment == nil || !result.Deployment.Activated ||
		result.Deployment.StartStatus != DeploymentStartCompleted || !result.RemoteExecuted {
		t.Fatalf("DeploySSHBinary() = %#v", result)
	}
	if deployer.calls != 1 || deployer.request.RemotePath != "/srv/app/service" ||
		deployer.request.ExpectedSize != int64(len(payload)) || deployer.request.ExpectedSHA256 != checksum {
		t.Fatalf("deployer request = %#v", deployer)
	}
	if !bytes.Equal(deployer.source, payload) {
		t.Fatalf("deployer source = %q, want %q", deployer.source, payload)
	}
	if deps.ssh.isolatedCalls != 1 || deps.ssh.command != "systemctl restart app.service" {
		t.Fatalf("start action dispatch = %#v", deps.ssh)
	}
	encoded := auditJSON(t, deps.audit.entries)
	if strings.Contains(encoded, string(payload)) || strings.Contains(encoded, sourcePath) {
		t.Fatalf("audit contains source data or retired identifiers: %s", encoded)
	}
}

func TestDeploySSHBinaryDisabledCapabilityNeverDispatches(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.sshTarget.AllowFileOperations = false
	deployer := &fakeSSHBinaryDeployer{}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})

	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: filepath.Join(t.TempDir(), "does-not-exist"), RemotePath: "/srv/app/service",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted ||
		result.FailureKind != FailureKindFileOperationsDisabled || deployer.calls != 0 || deps.ssh.calls != 0 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("disabled deployment = %#v, deployer = %#v, ssh = %#v", result, deployer, deps.ssh)
	}
	if len(deps.audit.entries) != 1 || deps.audit.entries[0].RemoteExecuted {
		t.Fatalf("disabled deployment audit = %#v", deps.audit.entries)
	}
}

func TestDeploySSHBinaryDisabledCapabilityWinsOverMissingDeployer(t *testing.T) {
	t.Parallel()

	deps := newFakeDependencies()
	deps.targets.sshTarget.AllowFileOperations = false
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})

	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: filepath.Join(t.TempDir(), "does-not-exist"), RemotePath: "/srv/app/service",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted || result.FailureKind != FailureKindFileOperationsDisabled || deps.ssh.calls != 0 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("disabled deployment without deployer = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestDeploySSHBinaryRejectsBlockedStartActionBeforeActivation(t *testing.T) {
	t.Parallel()

	payload := []byte("payload")
	deps := newFakeDependencies()
	deployer := &fakeSSHBinaryDeployer{result: sshtransport.BinaryDeploymentResult{
		RemotePath: "/srv/app/service", BackupPath: "/srv/app/.ssh-mcp-backup-1",
		BytesUploaded: int64(len(payload)), SHA256: digest(payload), Activated: true,
	}}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})

	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: writeDeploymentSource(t, payload), RemotePath: "/srv/app/service",
		StartAction: "rm -rf /",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted || result.FailureKind != FailureKindDeploymentSource || deployer.calls != 0 || deps.ssh.calls != 0 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("blocked start action = %#v, deployer = %#v, ssh = %#v", result, deployer, deps.ssh)
	}
}

func TestDeploySSHBinaryRejectsInvalidDestinationBeforeSourceOpen(t *testing.T) {
	t.Parallel()

	sourcePath := writeDeploymentSource(t, []byte("payload"))
	for _, remotePath := range []string{"", "srv/app/service", "/srv/app/../service", "/srv/app/service/", "/srv/app//service"} {
		t.Run(remotePath, func(t *testing.T) {
			deps := newFakeDependencies()
			deployer := &fakeSSHBinaryDeployer{}
			engine := New(Dependencies{
				Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
				Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
				Audit: deps.audit, OpenTUI: deps.OpenTUI,
			})
			result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
				Target: "192.0.2.10", SourcePath: sourcePath, RemotePath: remotePath,
			})
			if err != nil {
				t.Fatalf("DeploySSHBinary() error = %v", err)
			}
			if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted ||
				result.FailureKind != FailureKindDeploymentPath || deployer.calls != 0 {
				t.Fatalf("invalid destination = %#v, deployer = %#v", result, deployer)
			}
		})
	}
}

func TestDeploySSHBinaryRejectsOversizedSourceBeforeDispatch(t *testing.T) {
	t.Parallel()

	sourcePath := writeDeploymentSource(t, []byte("too large"))
	deps := newFakeDependencies()
	deployer := &fakeSSHBinaryDeployer{}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})
	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: sourcePath, RemotePath: "/srv/app/service", MaxBytes: 1,
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusRejected || result.ExecutionOutcome != StatusNotDispatched || result.RemoteExecuted || deployer.calls != 0 {
		t.Fatalf("oversized deployment = %#v, deployer = %#v", result, deployer)
	}
}

func TestDeploySSHBinaryDoesNotStartAfterUntrustedTransportResult(t *testing.T) {
	t.Parallel()

	payload := []byte("binary")
	checksum := digest(payload)
	deps := newFakeDependencies()
	deployer := &fakeSSHBinaryDeployer{result: sshtransport.BinaryDeploymentResult{
		RemotePath:    "/srv/app/other",
		BackupPath:    "/srv/app/.backup",
		BytesUploaded: int64(len(payload)),
		SHA256:        checksum,
		Activated:     true,
	}}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})
	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: writeDeploymentSource(t, payload),
		RemotePath: "/srv/app/service", StartAction: "systemctl restart app.service",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusOutcomeUnknown || result.ExecutionOutcome != StatusOutcomeUnknown ||
		result.FailureKind != FailureKindDeploymentUnknown || !result.RemoteExecuted || deps.ssh.calls != 0 || deps.ssh.isolatedCalls != 0 {
		t.Fatalf("untrusted deployment = %#v, ssh = %#v", result, deps.ssh)
	}
}

func TestDeploySSHBinaryMapsUnknownTransportOutcome(t *testing.T) {
	t.Parallel()

	payload := []byte("binary")
	deps := newFakeDependencies()
	deployer := &fakeSSHBinaryDeployer{
		err: sshtransport.ErrDeploymentOutcomeUnknown,
		result: sshtransport.BinaryDeploymentResult{
			RemotePath: "/srv/app/service", BackupPath: "/srv/app/.ssh-mcp-backup-1",
			BytesUploaded: int64(len(payload)), SHA256: digest(payload), Activated: false,
		},
	}
	engine := New(Dependencies{
		Targets: deps.targets, Sessions: deps.sessions, SSH: deps.ssh,
		Deployer: deployer, Database: deps.database, WorkSessions: deps.workSessions,
		Audit: deps.audit, OpenTUI: deps.OpenTUI,
	})
	result, err := engine.DeploySSHBinary(context.Background(), SSHBinaryDeploymentRequest{
		Target: "192.0.2.10", SourcePath: writeDeploymentSource(t, payload), RemotePath: "/srv/app/service",
	})
	if err != nil {
		t.Fatalf("DeploySSHBinary() error = %v", err)
	}
	if result.Status != StatusOutcomeUnknown || result.ExecutionOutcome != StatusOutcomeUnknown ||
		!result.RemoteExecuted || deployer.calls != 1 || deps.ssh.calls != 0 {
		t.Fatalf("unknown deployment = %#v, deployer = %#v, ssh = %#v", result, deployer, deps.ssh)
	}
}

func writeDeploymentSource(t *testing.T, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write deployment source: %v", err)
	}
	return path
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func auditJSON(t *testing.T, entries any) string {
	t.Helper()
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type fakeSSHBinaryDeployer struct {
	result  sshtransport.BinaryDeploymentResult
	err     error
	calls   int
	request sshtransport.BinaryDeploymentRequest
	source  []byte
}

func (d *fakeSSHBinaryDeployer) DeployBinary(_ context.Context, _ *store.Vault, _ store.SSHTarget, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	d.calls++
	d.request = request
	d.source, _ = io.ReadAll(source)
	return d.result, d.err
}

var _ SSHBinaryDeployer = (*fakeSSHBinaryDeployer)(nil)
