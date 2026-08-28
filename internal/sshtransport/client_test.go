package sshtransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestClientRejectsCanceledContextBeforeOpeningSession(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Client{}).Execute(ctx, "id -u", false, 1024); !errors.Is(err, ErrNotDispatched) {
		t.Fatalf("Execute() error = %v, want ErrNotDispatched", err)
	}
}

func TestHostKeyCallbackOnlyAcceptsPinnedFingerprint(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	fingerprint := ssh.FingerprintSHA256(publicKey)

	callback := hostKeyCallback(fingerprint)
	if err := callback("192.0.2.10:22", nil, publicKey); err != nil {
		t.Fatalf("pinned callback error = %v", err)
	}
	if err := hostKeyCallback("SHA256:not-the-server")("192.0.2.10:22", nil, publicKey); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("changed host key error = %v, want ErrHostKeyMismatch", err)
	}
}

func TestCappedBufferAndSudoCommandDoNotCreateInteractiveShell(t *testing.T) {
	t.Parallel()

	buffer := newCappedBuffer(4)
	if _, err := buffer.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := buffer.String(); got != "abcd" || !buffer.Truncated() {
		t.Fatalf("buffer = %q, truncated = %v", got, buffer.Truncated())
	}
	if got, err := commandForExecution("id -u", true); err != nil || got != "sudo -n -- /bin/sh -c 'id -u'" {
		t.Fatalf("sudo command = %q, error = %v", got, err)
	}
	if got, err := commandForExecution("mkdir -p /data/mysql && echo 'ready'", true); err != nil || !strings.HasPrefix(got, "sudo -n -- /bin/sh -c '") || !strings.Contains(got, "&&") {
		t.Fatalf("compound sudo command = %q, error = %v", got, err)
	}
	if got, err := commandForExecution("free -m", false); err != nil || got != "/bin/sh -c 'free -m'" {
		t.Fatalf("unprivileged command = %q, error = %v", got, err)
	}
	if _, err := commandForExecution("", false); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("empty command error = %v, want ErrInvalidCommand", err)
	}
}

func TestOutputBudgetCombinesStandardOutputAndError(t *testing.T) {
	t.Parallel()

	budget := newOutputBudget(4)
	stdout := newCappedBufferWithBudget(budget)
	stderr := newCappedBufferWithBudget(budget)
	if _, err := stdout.Write([]byte("abc")); err != nil {
		t.Fatalf("stdout Write() error = %v", err)
	}
	if _, err := stderr.Write([]byte("def")); err != nil {
		t.Fatalf("stderr Write() error = %v", err)
	}
	if stdout.String() != "abc" || stderr.String() != "d" || !budget.Truncated() {
		t.Fatalf("output budget = stdout:%q stderr:%q truncated:%t", stdout.String(), stderr.String(), budget.Truncated())
	}
	select {
	case <-budget.Reached():
	default:
		t.Fatal("output limit was not signaled")
	}
}
