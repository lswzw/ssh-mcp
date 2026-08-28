// Package sshtransport provides non-interactive SSH transport. It deliberately
// leaves command risk classification to the policy engine, while enforcing the
// pinned host-key and timeout boundaries required by every caller.
package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalidEndpoint = errors.New("invalid SSH endpoint")
	ErrHostKeyMismatch = errors.New("SSH host key fingerprint mismatch")
	ErrInvalidCommand  = errors.New("invalid SSH command")
	ErrNotDispatched   = errors.New("SSH command was not dispatched")
)

type Endpoint struct {
	Host        string
	Port        int
	Username    string
	Password    []byte
	Fingerprint string
}

type Client struct {
	client *ssh.Client

	// fileFactory is test-only dependency injection for the read-only SFTP
	// adapter. Production clients leave it nil and use the pinned SSH client.
	fileFactory func() (readOnlySFTP, error)

	// deploymentFactory is test-only dependency injection for the constrained
	// deployment adapter. Production clients leave it nil and use the pinned
	// SSH client.
	deploymentFactory func() (deploymentProtocol, error)
}

type ExecutionResult struct {
	Stdout          string
	Stderr          string
	ExitStatus      int
	OutputTruncated bool
}

// ProbeHostKey obtains a server fingerprint without accepting it for a real
// connection. The caller must display and confirm this value before Dial.
func ProbeHostKey(ctx context.Context, endpoint Endpoint) (string, error) {
	if err := validateEndpoint(endpoint, false); err != nil {
		return "", err
	}
	rawConnection, err := dialContext(ctx, endpoint)
	if err != nil {
		return "", err
	}
	defer rawConnection.Close()

	var fingerprint string
	config := &ssh.ClientConfig{
		User: endpoint.Username,
		Auth: []ssh.AuthMethod{ssh.Password(string(endpoint.Password))},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			return errHostKeyCollected
		},
	}
	_, _, _, _ = ssh.NewClientConn(rawConnection, endpointAddress(endpoint), config)
	if fingerprint == "" {
		return "", fmt.Errorf("read SSH host key fingerprint")
	}
	return fingerprint, nil
}

func Dial(ctx context.Context, endpoint Endpoint) (*Client, error) {
	if err := validateEndpoint(endpoint, true); err != nil {
		return nil, err
	}
	rawConnection, err := dialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            endpoint.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(string(endpoint.Password))},
		HostKeyCallback: hostKeyCallback(endpoint.Fingerprint),
	}
	connection, channels, requests, err := newClientConn(ctx, rawConnection, endpointAddress(endpoint), config)
	if err != nil {
		_ = rawConnection.Close()
		return nil, err
	}
	return &Client{client: ssh.NewClient(connection, channels, requests)}, nil
}

func (c *Client) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

func (c *Client) Execute(ctx context.Context, command string, asRoot bool, maxBytes int) (ExecutionResult, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: %w", ErrNotDispatched, err)
	}
	if c == nil || c.client == nil {
		return ExecutionResult{}, ErrInvalidEndpoint
	}
	command, err := commandForExecution(command, asRoot)
	if err != nil {
		return ExecutionResult{}, err
	}
	if maxBytes <= 0 {
		return ExecutionResult{}, ErrInvalidCommand
	}
	session, err := c.client.NewSession()
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: create SSH session: %w", ErrNotDispatched, err)
	}
	defer session.Close()
	budget := newOutputBudget(maxBytes)
	stdout := newCappedBufferWithBudget(budget)
	stderr := newCappedBufferWithBudget(budget)
	session.Stdout = stdout
	session.Stderr = stderr
	if err := ctx.Err(); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: %w", ErrNotDispatched, err)
	}
	if err := session.Start(command); err != nil {
		return ExecutionResult{}, fmt.Errorf("start SSH command: %w", err)
	}

	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	finished := make(chan struct{})
	defer close(finished)
	select {
	case err := <-wait:
		result := ExecutionResult{
			Stdout:          stdout.String(),
			Stderr:          stderr.String(),
			OutputTruncated: budget.Truncated(),
		}
		if err == nil {
			return result, nil
		}
		var exitError *ssh.ExitError
		if errors.As(err, &exitError) {
			result.ExitStatus = exitError.ExitStatus()
			return result, nil
		}
		return result, fmt.Errorf("wait for SSH command: %w", err)
	case <-budget.Reached():
		_ = session.Close()
		<-wait
		return ExecutionResult{Stdout: stdout.String(), Stderr: stderr.String(), OutputTruncated: true}, nil
	case <-ctx.Done():
		_ = session.Close()
		<-wait
		return ExecutionResult{}, ctx.Err()
	}
}

func hostKeyCallback(expectedFingerprint string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != expectedFingerprint {
			return ErrHostKeyMismatch
		}
		return nil
	}
}

func commandForExecution(command string, asRoot bool) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" || strings.ContainsRune(command, '\x00') {
		return "", ErrInvalidCommand
	}
	invocation := "/bin/sh -c " + shellQuote(command)
	if asRoot {
		return "sudo -n -- /bin/sh -c " + shellQuote(command), nil
	}
	return invocation, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func validateEndpoint(endpoint Endpoint, requireFingerprint bool) error {
	if _, err := netip.ParseAddr(endpoint.Host); err != nil || endpoint.Port < 1 || endpoint.Port > 65535 ||
		strings.TrimSpace(endpoint.Username) == "" || len(endpoint.Password) == 0 ||
		(requireFingerprint && strings.TrimSpace(endpoint.Fingerprint) == "") {
		return ErrInvalidEndpoint
	}
	return nil
}

func endpointAddress(endpoint Endpoint) string {
	return net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))
}

func dialContext(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpointAddress(endpoint))
	if err != nil {
		return nil, fmt.Errorf("dial SSH endpoint: %w", err)
	}
	return connection, nil
}

func newClientConn(ctx context.Context, rawConnection net.Conn, address string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConnection.Close()
		case <-done:
		}
	}()
	connection, channels, requests, err := ssh.NewClientConn(rawConnection, address, config)
	close(done)
	return connection, channels, requests, err
}

type cappedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
	budget    *outputBudget
}

func newCappedBuffer(limit int) *cappedBuffer {
	return newCappedBufferWithBudget(newOutputBudget(limit))
}

func newCappedBufferWithBudget(budget *outputBudget) *cappedBuffer {
	return &cappedBuffer{budget: budget}
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	allowed := b.budget.take(len(value))
	if allowed < len(value) {
		if allowed > 0 {
			_, _ = b.buffer.Write(value[:allowed])
		}
		b.truncated = true
		return len(value), nil
	}
	_, _ = b.buffer.Write(value)
	return len(value), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *cappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int
	truncated bool
	reached   chan struct{}
	once      sync.Once
}

func newOutputBudget(limit int) *outputBudget {
	return &outputBudget{remaining: limit, reached: make(chan struct{})}
}

func (b *outputBudget) take(size int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		b.truncated = true
		b.once.Do(func() { close(b.reached) })
		return 0
	}
	allowed := size
	if allowed > b.remaining {
		allowed = b.remaining
	}
	b.remaining -= allowed
	if allowed < size || b.remaining == 0 {
		b.truncated = true
		b.once.Do(func() { close(b.reached) })
	}
	return allowed
}

func (b *outputBudget) Reached() <-chan struct{} { return b.reached }

func (b *outputBudget) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

var errHostKeyCollected = errors.New("SSH host key fingerprint collected")
