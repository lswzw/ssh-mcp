package sshservice

import (
	"context"

	"ssh-mcp/internal/sshtransport"
)

// NativeTransport uses the production SSH client for host-key-pinned direct
// SSH target configuration tests.
type NativeTransport struct{}

type NativeExecutor struct{}

func (NativeTransport) ProbeHostKey(ctx context.Context, endpoint sshtransport.Endpoint) (string, error) {
	return sshtransport.ProbeHostKey(ctx, endpoint)
}

func (NativeTransport) TestCommand(ctx context.Context, endpoint sshtransport.Endpoint) error {
	client, err := sshtransport.Dial(ctx, endpoint)
	if err != nil {
		return err
	}
	defer client.Close()
	result, err := client.Execute(ctx, "true", false, 1024)
	if err != nil {
		return err
	}
	if result.ExitStatus != 0 {
		return &ExitStatusError{Status: result.ExitStatus}
	}
	return nil
}

func (NativeExecutor) Execute(ctx context.Context, endpoint sshtransport.Endpoint, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	client, err := sshtransport.Dial(ctx, endpoint)
	if err != nil {
		return sshtransport.ExecutionResult{}, err
	}
	defer client.Close()
	return client.Execute(ctx, command, asRoot, maxBytes)
}

type ExitStatusError struct {
	Status int
}

func (e *ExitStatusError) Error() string {
	return "SSH test command failed"
}
