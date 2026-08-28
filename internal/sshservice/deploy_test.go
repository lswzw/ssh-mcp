package sshservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"

	"ssh-mcp/internal/sshtransport"
)

func TestServiceDeployBinaryUsesPinnedIsolatedDeploymentCapability(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()

	payload := []byte("signed application archive")
	request := deploymentRequestForTest("/srv/app/bin/service.jar", payload)
	connection := &fakeIsolatedBinaryDeployer{result: sshtransport.BinaryDeploymentResult{
		RemotePath: request.RemotePath, BackupPath: "/srv/app/bin/.ssh-mcp-backup-test",
		BytesUploaded: int64(len(payload)), SHA256: request.ExpectedSHA256, Activated: true,
	}}
	dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	result, err := service.DeployBinary(context.Background(), vault, target, bytes.NewReader(payload), request)
	if err != nil {
		t.Fatalf("DeployBinary() error = %v", err)
	}
	if result != connection.result {
		t.Fatalf("DeployBinary() result = %#v, want %#v", result, connection.result)
	}
	if calls := connection.calls(); calls != 1 {
		t.Fatalf("deployment calls = %d, want 1", calls)
	}
	if got := connection.payload(0); !bytes.Equal(got, payload) {
		t.Fatalf("deployment payload = %q, want %q", got, payload)
	}
	if got := connection.request(0); got != request {
		t.Fatalf("deployment request = %#v, want %#v", got, request)
	}
	if connection.executeCalls() != 0 {
		t.Fatal("deployment was downgraded to generic command execution")
	}
	endpoint := dialer.endpoint(0)
	if endpoint.Host != target.IP || endpoint.Port != target.SSHPort || endpoint.Username != target.LoginUsername ||
		endpoint.Fingerprint != "SHA256:pinned" || string(endpoint.Password) != "password" {
		t.Fatalf("deployment endpoint = %#v", endpoint)
	}

	service.isolated.mu.Lock()
	defer service.isolated.mu.Unlock()
	if len(service.isolated.entries) != 1 {
		t.Fatalf("isolated entries = %d, want 1", len(service.isolated.entries))
	}
	for key := range service.isolated.entries {
		if key.Target != target.IP || key.TargetRevision != target.Revision || key.SpecificationVersion != controlledBinaryDeploymentSpecificationVersion {
			t.Fatalf("deployment isolated key = %#v", key)
		}
	}
}

func TestServiceDeployBinaryRejectsPreDispatchRevocationAndCancellation(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	payload := []byte("source")
	request := deploymentRequestForTest("/srv/app/bin/service", payload)

	t.Run("canceled", func(t *testing.T) {
		connection := &fakeIsolatedBinaryDeployer{}
		dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
		service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reader := &countingDeploymentReader{payload: payload}

		_, err := service.DeployBinary(ctx, vault, target, reader, request)
		if !errors.Is(err, sshtransport.ErrNotDispatched) {
			t.Fatalf("DeployBinary() error = %v, want ErrNotDispatched", err)
		}
		if dialer.calls() != 0 || reader.reads() != 0 || connection.calls() != 0 {
			t.Fatalf("canceled deployment dispatched: dials=%d reads=%d deployments=%d", dialer.calls(), reader.reads(), connection.calls())
		}
	})

	t.Run("target revision changed", func(t *testing.T) {
		connection := &fakeIsolatedBinaryDeployer{}
		dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
		service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)
		changed := target
		changed.LoginUsername = "deploy"
		if err := credentialStore.UpsertSSHTarget(context.Background(), changed); err != nil {
			t.Fatalf("UpsertSSHTarget() error = %v", err)
		}
		reader := &countingDeploymentReader{payload: payload}

		_, err := service.DeployBinary(context.Background(), vault, target, reader, request)
		if !errors.Is(err, sshtransport.ErrNotDispatched) {
			t.Fatalf("DeployBinary() error = %v, want ErrNotDispatched", err)
		}
		if dialer.calls() != 0 || reader.reads() != 0 || connection.calls() != 0 {
			t.Fatalf("stale deployment dispatched: dials=%d reads=%d deployments=%d", dialer.calls(), reader.reads(), connection.calls())
		}
	})
}

func TestServiceDeployBinaryRejectsConnectionWithoutDeploymentCapability(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	connection := &fakeIsolatedConnection{}
	dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)
	payload := []byte("source")

	_, err := service.DeployBinary(context.Background(), vault, target, bytes.NewReader(payload), deploymentRequestForTest("/srv/app/bin/service", payload))
	if !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("DeployBinary() error = %v, want ErrNotDispatched", err)
	}
	if got := connection.commands(); len(got) != 0 {
		t.Fatalf("generic commands = %#v, want none", got)
	}
}

func TestServiceDeployBinaryDiscardsFailedIsolatedConnection(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	payload := []byte("source")
	connection := &fakeIsolatedBinaryDeployer{err: sshtransport.ErrDeploymentOutcomeUnknown}
	dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	_, err := service.DeployBinary(context.Background(), vault, target, bytes.NewReader(payload), deploymentRequestForTest("/srv/app/bin/service", payload))
	if !errors.Is(err, sshtransport.ErrDeploymentOutcomeUnknown) {
		t.Fatalf("DeployBinary() error = %v, want transport outcome", err)
	}
	if !connection.closed() {
		t.Fatal("failed deployment did not discard its isolated connection")
	}
}

func TestIsolatedDeploymentLeaseRejectsRevokedTargetBeforeDialOrSourceRead(t *testing.T) {
	t.Parallel()

	connection := &fakeIsolatedBinaryDeployer{}
	dialer := &binaryDeployDialer{connections: []IsolatedConnection{connection}}
	pool := newIsolatedConnectionPool(dialer)
	key := isolatedConnectionKey{
		Target: "192.0.2.250", TargetRevision: 1, Port: 22, Username: "ops",
		CredentialID: "ssh-password", Fingerprint: "SHA256:pinned",
		SpecificationVersion: controlledBinaryDeploymentSpecificationVersion,
	}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	payload := []byte("source")
	reader := &countingDeploymentReader{payload: payload}
	lease, err := pool.AcquireTarget(key.Target)
	if err != nil {
		t.Fatalf("AcquireTarget() error = %v", err)
	}
	pool.InvalidateTarget(key.Target)
	pool.ActivateTarget(key.Target)

	_, err = lease.DeployBinary(context.Background(), key, endpoint, reader, deploymentRequestForTest("/srv/app/bin/service", payload))
	if !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("stale DeployBinary() error = %v, want ErrNotDispatched", err)
	}
	if dialer.calls() != 0 || reader.reads() != 0 || connection.calls() != 0 {
		t.Fatalf("stale deployment dispatched: dials=%d reads=%d deployments=%d", dialer.calls(), reader.reads(), connection.calls())
	}
}

func deploymentRequestForTest(remotePath string, payload []byte) sshtransport.BinaryDeploymentRequest {
	digest := sha256.Sum256(payload)
	return sshtransport.BinaryDeploymentRequest{
		RemotePath: remotePath, ExpectedSize: int64(len(payload)),
		ExpectedSHA256: hex.EncodeToString(digest[:]), MaxBytes: int64(len(payload)),
	}
}

type binaryDeployDialer struct {
	mu          sync.Mutex
	connections []IsolatedConnection
	endpoints   []sshtransport.Endpoint
}

func (d *binaryDeployDialer) Dial(_ context.Context, endpoint sshtransport.Endpoint) (IsolatedConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	endpoint.Password = append([]byte(nil), endpoint.Password...)
	d.endpoints = append(d.endpoints, endpoint)
	index := len(d.endpoints) - 1
	if index >= len(d.connections) {
		return nil, errors.New("unexpected isolated deployment dial")
	}
	return d.connections[index], nil
}

func (d *binaryDeployDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.endpoints)
}

func (d *binaryDeployDialer) endpoint(index int) sshtransport.Endpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.endpoints[index]
}

type fakeIsolatedBinaryDeployer struct {
	mu       sync.Mutex
	result   sshtransport.BinaryDeploymentResult
	err      error
	requests []sshtransport.BinaryDeploymentRequest
	payloads [][]byte
	executes int
	closes   int
}

func (c *fakeIsolatedBinaryDeployer) Execute(context.Context, string, bool, int) (sshtransport.ExecutionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.executes++
	return sshtransport.ExecutionResult{}, nil
}

func (c *fakeIsolatedBinaryDeployer) DeployBinary(_ context.Context, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	payload, readErr := io.ReadAll(source)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
	c.payloads = append(c.payloads, append([]byte(nil), payload...))
	if readErr != nil {
		return sshtransport.BinaryDeploymentResult{}, readErr
	}
	return c.result, c.err
}

func (c *fakeIsolatedBinaryDeployer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return nil
}

func (c *fakeIsolatedBinaryDeployer) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeIsolatedBinaryDeployer) payload(index int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.payloads[index]...)
}

func (c *fakeIsolatedBinaryDeployer) request(index int) sshtransport.BinaryDeploymentRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[index]
}

func (c *fakeIsolatedBinaryDeployer) executeCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.executes
}

func (c *fakeIsolatedBinaryDeployer) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes > 0
}

type countingDeploymentReader struct {
	mu      sync.Mutex
	payload []byte
	offset  int
}

func (r *countingDeploymentReader) Read(destination []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offset >= len(r.payload) {
		return 0, io.EOF
	}
	read := copy(destination, r.payload[r.offset:])
	r.offset += read
	return read, nil
}

func (r *countingDeploymentReader) reads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.offset
}
