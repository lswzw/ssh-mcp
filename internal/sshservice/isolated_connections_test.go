package sshservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

func TestServiceDeploysBinaryThroughPinnedIsolatedConnection(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	connection := &fakeBinaryIsolatedConnection{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, singleIsolatedConnectionDialer{connection: connection})
	payload := []byte("binary payload")
	result, err := service.DeployBinary(context.Background(), vault, target, bytes.NewReader(payload), sshtransport.BinaryDeploymentRequest{
		RemotePath: "/srv/app/bin/service", ExpectedSize: int64(len(payload)), ExpectedSHA256: deployDigest(payload), MaxBytes: int64(len(payload)),
	})
	if err != nil {
		t.Fatalf("DeployBinary() error = %v", err)
	}
	if !result.Activated || connection.calls != 1 || connection.request.RemotePath != "/srv/app/bin/service" || !bytes.Equal(connection.payload, payload) {
		t.Fatalf("DeployBinary() = %#v, connection = %#v", result, connection)
	}
}

func TestServiceRejectsBinaryDeploymentWhenPinnedConnectionHasNoDeploymentProtocol(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	connection := &fakeIsolatedConnection{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, singleIsolatedConnectionDialer{connection: connection})
	_, err := service.DeployBinary(context.Background(), vault, target, bytes.NewReader([]byte("x")), sshtransport.BinaryDeploymentRequest{
		RemotePath: "/srv/app/bin/service", ExpectedSize: 1, ExpectedSHA256: deployDigest([]byte("x")), MaxBytes: 1,
	})
	if err == nil || !errors.Is(err, errBinaryDeploymentUnavailable) {
		t.Fatalf("DeployBinary() error = %v, want unavailable", err)
	}
	if connection.commands() != nil {
		t.Fatalf("unsupported connection received command calls: %#v", connection.commands())
	}
}

func deployDigest(payload []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

type fakeBinaryIsolatedConnection struct {
	fakeIsolatedConnection
	payload []byte
	request sshtransport.BinaryDeploymentRequest
	calls   int
}

func (c *fakeBinaryIsolatedConnection) DeployBinary(_ context.Context, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	c.calls++
	c.request = request
	c.payload, _ = io.ReadAll(source)
	return sshtransport.BinaryDeploymentResult{RemotePath: request.RemotePath, BackupPath: "/srv/app/bin/.backup", BytesUploaded: int64(len(c.payload)), SHA256: request.ExpectedSHA256, Activated: true}, nil
}

func TestServiceReusesIsolatedConnectionForSameExecutionIdentity(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	for _, command := range []string{"free -m", "uptime"} {
		if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, command, false, 1024); err != nil {
			t.Fatalf("ExecuteIsolated(%q) error = %v", command, err)
		}
	}

	if dialer.calls() != 1 {
		t.Fatalf("Dial() calls = %d, want 1", dialer.calls())
	}
	connection := dialer.connection(0)
	if got, want := connection.commands(), []string{"free -m", "uptime"}; !sameStrings(got, want) {
		t.Fatalf("connection commands = %#v, want %#v", got, want)
	}
	if connection.closed() {
		t.Fatal("reused connection was closed")
	}
}

func TestServiceSeparatesIsolatedConnectionsBySpecificationAndTargetRevision(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	if _, err := service.ExecuteIsolated(context.Background(), vault, target, "spec-v1", "free -m", false, 1024); err != nil {
		t.Fatalf("first ExecuteIsolated() error = %v", err)
	}
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, "spec-v2", "uptime", false, 1024); err != nil {
		t.Fatalf("spec-changed ExecuteIsolated() error = %v", err)
	}
	if dialer.calls() != 2 || !dialer.connection(0).closed() {
		t.Fatalf("spec change calls = %d, first closed = %t", dialer.calls(), dialer.connection(0).closed())
	}

	target.LoginUsername = "deploy"
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	target, err := credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		t.Fatalf("SSHTarget() error = %v", err)
	}
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, "spec-v2", "hostname", false, 1024); err != nil {
		t.Fatalf("revision-changed ExecuteIsolated() error = %v", err)
	}
	if dialer.calls() != 3 || !dialer.connection(1).closed() {
		t.Fatalf("revision change calls = %d, second closed = %t", dialer.calls(), dialer.connection(1).closed())
	}
	if err := credentialStore.ReplaceHostKey(context.Background(), target.IP, target.SSHPort, "SHA256:replacement"); err != nil {
		t.Fatalf("ReplaceHostKey() error = %v", err)
	}
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, "spec-v2", "uname -a", false, 1024); err != nil {
		t.Fatalf("fingerprint-changed ExecuteIsolated() error = %v", err)
	}
	if dialer.calls() != 4 || !dialer.connection(2).closed() {
		t.Fatalf("fingerprint change calls = %d, third closed = %t", dialer.calls(), dialer.connection(2).closed())
	}
}

func TestServiceInvalidatesIsolatedConnectionOnTargetRevocationAndTransportError(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "free -m", false, 1024); err != nil {
		t.Fatalf("first ExecuteIsolated() error = %v", err)
	}
	service.CloseTarget(target.IP)
	if !dialer.connection(0).closed() {
		t.Fatal("target revocation did not close the connection")
	}
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "uptime", false, 1024); err != nil {
		t.Fatalf("ExecuteIsolated() after target revocation error = %v", err)
	}
	if dialer.calls() != 2 {
		t.Fatalf("Dial() calls after target revocation = %d, want 2", dialer.calls())
	}

	dialer.connection(1).setError(errors.New("connection reset"))
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "df -h", false, 1024); err == nil {
		t.Fatal("ExecuteIsolated() after connection error = nil")
	}
	if !dialer.connection(1).closed() || dialer.calls() != 2 {
		t.Fatalf("connection error closed = %t, dials = %d", dialer.connection(1).closed(), dialer.calls())
	}
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "hostname", false, 1024); err != nil {
		t.Fatalf("ExecuteIsolated() after connection error error = %v", err)
	}
	if dialer.calls() != 3 {
		t.Fatalf("Dial() calls after connection error = %d, want 3", dialer.calls())
	}
}

func TestServiceMarksFailedIsolatedDialAsNotDispatched(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{dialErr: errors.New("authentication failed")}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	_, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "free -m", false, 1024)
	if !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("ExecuteIsolated() error = %v, want ErrNotDispatched", err)
	}
	if dialer.calls() != 1 {
		t.Fatalf("Dial() calls = %d, want 1", dialer.calls())
	}
}

func TestServiceBlocksIsolatedExecutionUntilTargetActivation(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)

	service.InvalidateTarget(target.IP)
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "free -m", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("ExecuteIsolated() while target is invalidated error = %v, want ErrNotDispatched", err)
	}
	if dialer.calls() != 0 {
		t.Fatalf("Dial() calls while target is invalidated = %d, want 0", dialer.calls())
	}

	service.ActivateTarget(target.IP)
	if _, err := service.ExecuteIsolated(context.Background(), vault, target, policy.Version, "uptime", false, 1024); err != nil {
		t.Fatalf("ExecuteIsolated() after target activation error = %v", err)
	}
	if dialer.calls() != 1 {
		t.Fatalf("Dial() calls after target activation = %d, want 1", dialer.calls())
	}
}

func TestServiceMarksCanceledIsolatedPreparationAsNotDispatched(t *testing.T) {
	t.Parallel()

	credentialStore, vault, target := isolatedExecutionFixture(t)
	defer credentialStore.Close()
	defer vault.Lock()
	dialer := &fakeIsolatedDialer{}
	service := NewWithIsolatedDialer(credentialStore, &fakeTransport{}, dialer)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.ExecuteIsolated(canceled, vault, target, policy.Version, "free -m", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("ExecuteIsolated() with canceled context error = %v, want ErrNotDispatched", err)
	}
	if dialer.calls() != 0 {
		t.Fatalf("Dial() calls with canceled context = %d, want 0", dialer.calls())
	}
}

func TestIsolatedConnectionPoolRunsConcurrentCommandsOnIndependentSessions(t *testing.T) {
	t.Parallel()

	connection := &blockingIsolatedConnection{started: make(chan string, 2), release: make(chan struct{}, 2)}
	pool := newIsolatedConnectionPool(singleIsolatedConnectionDialer{connection: connection})
	key := isolatedConnectionKey{Target: "192.0.2.30", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	type execution struct {
		result sshtransport.ExecutionResult
		err    error
	}
	results := make(chan execution, 2)
	go func() {
		result, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024)
		results <- execution{result: result, err: err}
	}()
	if command := <-connection.started; command != "free -m" {
		t.Fatalf("first command = %q", command)
	}
	go func() {
		result, err := pool.Execute(context.Background(), key, endpoint, "uptime", false, 1024)
		results <- execution{result: result, err: err}
	}()
	select {
	case command := <-connection.started:
		if command != "uptime" {
			t.Fatalf("second command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("second command did not start concurrently")
	}
	connection.release <- struct{}{}
	connection.release <- struct{}{}

	outputs := make([]string, 0, 2)
	for range 2 {
		executed := <-results
		if executed.err != nil {
			t.Fatalf("pool Execute() error = %v", executed.err)
		}
		outputs = append(outputs, executed.result.Stdout)
	}
	if connection.maxActiveCalls() != 2 || !sameStrings(outputs, []string{"free -m", "uptime"}) && !sameStrings(outputs, []string{"uptime", "free -m"}) {
		t.Fatalf("max active = %d, outputs = %#v", connection.maxActiveCalls(), outputs)
	}
}

func TestIsolatedConnectionPoolRejectsStaleLeaseAfterTargetRevocation(t *testing.T) {
	t.Parallel()

	dialer := &fakeIsolatedDialer{}
	pool := newIsolatedConnectionPool(dialer)
	key := isolatedConnectionKey{Target: "192.0.2.30", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	lease, err := pool.AcquireTarget(key.Target)
	if err != nil {
		t.Fatalf("AcquireTarget() error = %v", err)
	}
	pool.InvalidateTarget(key.Target)
	pool.ActivateTarget(key.Target)
	if _, err := lease.Execute(context.Background(), key, endpoint, "free -m", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("stale lease Execute() error = %v, want ErrNotDispatched", err)
	}
	if dialer.calls() != 0 {
		t.Fatalf("stale lease dialed %d connections", dialer.calls())
	}
	if _, err := pool.Execute(context.Background(), key, endpoint, "uptime", false, 1024); err != nil {
		t.Fatalf("fresh Execute() error = %v", err)
	}
	if dialer.calls() != 1 {
		t.Fatalf("fresh Execute() dials = %d, want 1", dialer.calls())
	}
}

func TestIsolatedConnectionPoolSuspendsOldLeasesUntilResume(t *testing.T) {
	t.Parallel()

	dialer := &fakeIsolatedDialer{}
	pool := newIsolatedConnectionPool(dialer)
	key := isolatedConnectionKey{Target: "192.0.2.35", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	if _, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	lease, err := pool.AcquireTarget(key.Target)
	if err != nil {
		t.Fatalf("AcquireTarget() error = %v", err)
	}
	if err := pool.Suspend(); err != nil {
		t.Fatalf("Suspend() error = %v", err)
	}
	if !dialer.connection(0).closed() {
		t.Fatal("Suspend() did not close the established connection")
	}
	if _, err := lease.Execute(context.Background(), key, endpoint, "uptime", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("stale lease Execute() while suspended error = %v, want ErrNotDispatched", err)
	}
	if _, err := pool.AcquireTarget(key.Target); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("AcquireTarget() while suspended error = %v, want ErrNotDispatched", err)
	}

	pool.Resume()
	if _, err := lease.Execute(context.Background(), key, endpoint, "hostname", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("stale lease Execute() after Resume() error = %v, want ErrNotDispatched", err)
	}
	if _, err := pool.Execute(context.Background(), key, endpoint, "uname -a", false, 1024); err != nil {
		t.Fatalf("fresh Execute() after Resume() error = %v", err)
	}
	if dialer.calls() != 2 {
		t.Fatalf("Dial() calls after Resume() = %d, want 2", dialer.calls())
	}
}

func TestIsolatedConnectionPoolSuspendWaitsForActiveDispatchAndRejectsNewCommands(t *testing.T) {
	t.Parallel()

	connection := &blockingIsolatedConnection{
		started: make(chan string, 1), release: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	pool := newIsolatedConnectionPool(singleIsolatedConnectionDialer{connection: connection})
	key := isolatedConnectionKey{Target: "192.0.2.36", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	executed := make(chan error, 1)
	go func() {
		_, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024)
		executed <- err
	}()
	if command := <-connection.started; command != "free -m" {
		t.Fatalf("active command = %q", command)
	}

	suspended := make(chan error, 1)
	go func() { suspended <- pool.Suspend() }()
	select {
	case <-connection.closed:
	case <-time.After(time.Second):
		t.Fatal("Suspend() did not close the active connection")
	}
	if _, err := pool.Execute(context.Background(), key, endpoint, "uptime", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("Execute() while suspension is pending error = %v, want ErrNotDispatched", err)
	}
	select {
	case err := <-suspended:
		t.Fatalf("Suspend() returned before active dispatch completed: %v", err)
	case <-time.After(10 * time.Millisecond):
	}

	connection.release <- struct{}{}
	if err := <-executed; err != nil {
		t.Fatalf("active Execute() error = %v", err)
	}
	if err := <-suspended; err != nil {
		t.Fatalf("Suspend() error = %v", err)
	}
}

func TestIsolatedConnectionPoolReopensAfterConcurrentLifecycleClosures(t *testing.T) {
	t.Parallel()

	connection := &blockingIsolatedConnection{
		started: make(chan string, 1), release: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	pool := newIsolatedConnectionPool(singleIsolatedConnectionDialer{connection: connection})
	key := isolatedConnectionKey{Target: "192.0.2.34", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	executed := make(chan error, 1)
	go func() {
		_, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024)
		executed <- err
	}()
	if command := <-connection.started; command != "free -m" {
		t.Fatalf("active command = %q", command)
	}
	firstDone := make(chan struct{})
	go func() {
		pool.CloseTarget(key.Target)
		close(firstDone)
	}()
	waitForLifecycleFlushes(t, pool, key.Target, 1)
	secondDone := make(chan struct{})
	go func() {
		pool.CloseTarget(key.Target)
		close(secondDone)
	}()
	waitForLifecycleFlushes(t, pool, key.Target, 2)
	select {
	case <-firstDone:
		t.Fatal("first CloseTarget() returned before active dispatch completed")
	case <-secondDone:
		t.Fatal("second CloseTarget() returned before active dispatch completed")
	case <-time.After(10 * time.Millisecond):
	}
	connection.release <- struct{}{}
	if err := <-executed; err != nil {
		t.Fatalf("active Execute() error = %v", err)
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first CloseTarget() did not return")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second CloseTarget() did not return")
	}
	if _, err := pool.AcquireTarget(key.Target); err != nil {
		t.Fatalf("AcquireTarget() after concurrent CloseTarget() calls error = %v", err)
	}
}

func TestIsolatedConnectionPoolWaitsForActiveDispatchWhenInvalidatingTarget(t *testing.T) {
	t.Parallel()

	connection := &blockingIsolatedConnection{
		started: make(chan string, 2), release: make(chan struct{}, 2), closed: make(chan struct{}),
	}
	pool := newIsolatedConnectionPool(singleIsolatedConnectionDialer{connection: connection})
	key := isolatedConnectionKey{Target: "192.0.2.31", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	executed := make(chan error, 2)
	for _, command := range []string{"free -m", "uptime"} {
		go func(command string) {
			_, err := pool.Execute(context.Background(), key, endpoint, command, false, 1024)
			executed <- err
		}(command)
	}
	started := make(map[string]bool, 2)
	for range 2 {
		select {
		case command := <-connection.started:
			started[command] = true
		case <-time.After(time.Second):
			t.Fatal("active commands did not start")
		}
	}
	if !started["free -m"] || !started["uptime"] {
		t.Fatalf("active commands = %#v", started)
	}

	invalidated := make(chan struct{})
	go func() {
		pool.InvalidateTarget(key.Target)
		close(invalidated)
	}()
	select {
	case <-connection.closed:
	case <-time.After(time.Second):
		t.Fatal("InvalidateTarget() did not close the active connection")
	}
	select {
	case <-invalidated:
		t.Fatal("InvalidateTarget() returned before the active dispatch completed")
	case <-time.After(10 * time.Millisecond):
	}

	connection.release <- struct{}{}
	if err := <-executed; err != nil {
		t.Fatalf("first active Execute() error = %v", err)
	}
	select {
	case <-invalidated:
		t.Fatal("InvalidateTarget() returned before all active dispatches completed")
	case <-time.After(10 * time.Millisecond):
	}
	connection.release <- struct{}{}
	if err := <-executed; err != nil {
		t.Fatalf("second active Execute() error = %v", err)
	}
	select {
	case <-invalidated:
	case <-time.After(time.Second):
		t.Fatal("InvalidateTarget() did not finish after the active dispatch completed")
	}
	if _, err := pool.Execute(context.Background(), key, endpoint, "uptime", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("Execute() while target is invalidated error = %v, want ErrNotDispatched", err)
	}
}

func TestIsolatedConnectionPoolDoesNotDispatchCanceledCommand(t *testing.T) {
	t.Parallel()

	dialer := &fakeIsolatedDialer{}
	pool := newIsolatedConnectionPool(dialer)
	key := isolatedConnectionKey{Target: "192.0.2.32", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	if _, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.Execute(canceled, key, endpoint, "uptime", false, 1024); !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("canceled Execute() error = %v, want ErrNotDispatched", err)
	}
	if got, want := dialer.connection(0).commands(), []string{"free -m"}; !sameStrings(got, want) {
		t.Fatalf("connection commands = %#v, want %#v", got, want)
	}
}

func TestIsolatedConnectionPoolDoesNotDispatchCanceledCommandWhileWaitingForConnection(t *testing.T) {
	t.Parallel()

	connection := &fakeIsolatedConnection{}
	dialer := &blockingIsolatedDialer{connection: connection, started: make(chan struct{}, 1), release: make(chan struct{})}
	pool := newIsolatedConnectionPool(dialer)
	key := isolatedConnectionKey{Target: "192.0.2.33", TargetRevision: 1, Port: 22, Username: "ops", CredentialID: "ssh-password", Fingerprint: "SHA256:pinned", SpecificationVersion: policy.Version}
	endpoint := sshtransport.Endpoint{Host: key.Target, Port: key.Port, Username: key.Username, Password: []byte("password"), Fingerprint: key.Fingerprint}
	firstExecuted := make(chan error, 1)
	go func() {
		_, err := pool.Execute(context.Background(), key, endpoint, "free -m", false, 1024)
		firstExecuted <- err
	}()
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("first command did not begin dialing")
	}
	canceled, cancel := context.WithCancel(context.Background())
	executed := make(chan error, 1)
	go func() {
		_, err := pool.Execute(canceled, key, endpoint, "uptime", false, 1024)
		executed <- err
	}()
	select {
	case err := <-executed:
		t.Fatalf("second Execute() returned before cancellation: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	if err := <-executed; !errors.Is(err, sshtransport.ErrNotDispatched) {
		t.Fatalf("Execute() after cancellation error = %v, want ErrNotDispatched", err)
	}
	close(dialer.release)
	if err := <-firstExecuted; err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
	if got, want := connection.commands(), []string{"free -m"}; !sameStrings(got, want) {
		t.Fatalf("connection commands = %#v, want %#v", got, want)
	}
}

func isolatedExecutionFixture(t *testing.T) (*store.Store, *store.Vault, store.SSHTarget) {
	t.Helper()
	credentialStore, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	vault, err := credentialStore.Initialize(context.Background(), []byte("master-password"))
	if err != nil {
		_ = credentialStore.Close()
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := vault.PutCredential(context.Background(), "ssh-password", "ssh", []byte("password")); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("PutCredential() error = %v", err)
	}
	target := store.SSHTarget{IP: "192.0.2.30", Mode: store.SSHDirect, SSHPort: 22, LoginUsername: "ops", CredentialID: "ssh-password", Enabled: true, IdentityStatus: store.SSHIdentityVerified}
	if err := credentialStore.UpsertSSHTarget(context.Background(), target); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("UpsertSSHTarget() error = %v", err)
	}
	if err := credentialStore.PinInitialHostKey(context.Background(), target.IP, target.SSHPort, "SHA256:pinned"); err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("PinInitialHostKey() error = %v", err)
	}
	target, err = credentialStore.SSHTarget(context.Background(), target.IP)
	if err != nil {
		vault.Lock()
		_ = credentialStore.Close()
		t.Fatalf("SSHTarget() error = %v", err)
	}
	return credentialStore, vault, target
}

type fakeIsolatedDialer struct {
	mu          sync.Mutex
	attempts    int
	dialErr     error
	connections []*fakeIsolatedConnection
}

func (d *fakeIsolatedDialer) Dial(_ context.Context, endpoint sshtransport.Endpoint) (IsolatedConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attempts++
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	connection := &fakeIsolatedConnection{endpoint: endpoint}
	d.connections = append(d.connections, connection)
	return connection, nil
}

func (d *fakeIsolatedDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.attempts
}

func (d *fakeIsolatedDialer) connection(index int) *fakeIsolatedConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.connections) {
		panic(fmt.Sprintf("connection index %d out of range", index))
	}
	return d.connections[index]
}

type fakeIsolatedConnection struct {
	mu       sync.Mutex
	endpoint sshtransport.Endpoint
	command  []string
	err      error
	closedAt int
}

func (c *fakeIsolatedConnection) Execute(_ context.Context, command string, _ bool, _ int) (sshtransport.ExecutionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.command = append(c.command, command)
	return sshtransport.ExecutionResult{Stdout: command}, c.err
}

func (c *fakeIsolatedConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closedAt++
	return nil
}

func (c *fakeIsolatedConnection) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *fakeIsolatedConnection) commands() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.command...)
}

func (c *fakeIsolatedConnection) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closedAt > 0
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func waitForLifecycleFlushes(t *testing.T, pool *isolatedConnectionPool, target string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		gate := pool.targets[target]
		got := 0
		if gate != nil {
			got = gate.lifecycleFlushes
		}
		pool.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lifecycle flushes for %q did not reach %d", target, want)
}

type singleIsolatedConnectionDialer struct {
	connection IsolatedConnection
}

func (d singleIsolatedConnectionDialer) Dial(context.Context, sshtransport.Endpoint) (IsolatedConnection, error) {
	return d.connection, nil
}

type blockingIsolatedDialer struct {
	connection IsolatedConnection
	started    chan struct{}
	release    chan struct{}
}

func (d *blockingIsolatedDialer) Dial(ctx context.Context, _ sshtransport.Endpoint) (IsolatedConnection, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return d.connection, nil
	}
}

type blockingIsolatedConnection struct {
	mu      sync.Mutex
	started chan string
	release chan struct{}
	closed  chan struct{}
	close   sync.Once
	active  int
	max     int
}

func (c *blockingIsolatedConnection) Execute(ctx context.Context, command string, _ bool, _ int) (sshtransport.ExecutionResult, error) {
	c.mu.Lock()
	c.active++
	if c.active > c.max {
		c.max = c.active
	}
	c.mu.Unlock()
	c.started <- command
	select {
	case <-ctx.Done():
		return sshtransport.ExecutionResult{}, ctx.Err()
	case <-c.release:
	}
	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	return sshtransport.ExecutionResult{Stdout: command}, nil
}

func (c *blockingIsolatedConnection) Close() error {
	if c.closed != nil {
		c.close.Do(func() { close(c.closed) })
	}
	return nil
}

func (c *blockingIsolatedConnection) maxActiveCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}
