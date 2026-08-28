package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/instance"
	"ssh-mcp/internal/paths"
)

const (
	daemonStartTimeout     = 5 * time.Second
	bridgeResponseGrace    = time.Second
	daemonStopTimeout      = time.Second
	daemonStopPollInterval = 25 * time.Millisecond
	daemonStartupFDEnv     = "SSH_MCP_DAEMON_STARTUP_FD"
	daemonStartupReady     = "ready"
	daemonStartupError     = "error:"
	daemonStartupChildFD   = 3
)

var (
	ErrDaemonNotRunning  = errors.New("ssh-mcp daemon is not running")
	ErrDaemonBusy        = errors.New("ssh-mcp daemon has active bridge sessions")
	errDaemonPIDMarker   = errors.New("daemon PID marker is invalid")
	errDaemonPIDMismatch = errors.New("daemon PID marker does not match the running process")
)

const daemonPIDMarkerVersion = "ssh-mcp-daemon-v1"

// daemonPIDMarker identifies a daemon process without relying on a PID alone.
// StartTime is supplied by the platform process identity backend and changes
// whenever the operating system reuses a PID.
type daemonPIDMarker struct {
	PID       int
	StartTime uint64
}

type daemonStopExecutor interface {
	Status(context.Context) (DaemonStatus, error)
	PrepareForceStop(context.Context) error
	Shutdown(context.Context) error
	Close(context.Context) error
}

func RunDaemon(ctx context.Context) error {
	return runDaemon(ctx, RuntimeOptions{})
}

func runDaemon(ctx context.Context, options RuntimeOptions) error {
	runtime, err := NewRuntime(options)
	if err != nil {
		reportDaemonStartup(err)
		return err
	}
	defer runtime.Close()
	if err := runtime.Start(); err != nil {
		reportDaemonStartup(err)
		return err
	}
	reportDaemonStartup(nil)

	idle := make(chan error, 1)
	go func() { idle <- runtime.WaitForIdle(ctx) }()
	for {
		select {
		case err := <-idle:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-ctx.Done():
			return nil
		case <-runtime.shutdownRequested:
			return nil
		}
	}
}

func connectOrStartDaemon(ctx context.Context, options RuntimeOptions) (*bridgeExecutor, error) {
	roots, err := resolveRoots(options)
	if err != nil {
		return nil, err
	}
	socketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	client, err := bridge.Connect(ctx, socketPath)
	if err == nil {
		return readyBridgeExecutor(ctx, client)
	}
	if errors.Is(err, bridge.ErrVersionMismatch) {
		return nil, err
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, daemonStartTimeout)
	defer cancelStartup()
	startErr := startConfiguredDaemon(startupContext, options)
	if startErr != nil {
		// Tests and callers that inject a starter expect its own failure to be
		// returned directly. The real process starter can lose a startup race to
		// another bridge, so wait for that daemon before reporting its error.
		if options.daemonStarter != nil {
			return nil, startErr
		}
		executor, waitErr := waitForReadyDaemon(ctx, socketPath, time.Now().Add(daemonStartTimeout))
		if waitErr == nil {
			return executor, nil
		}
		return nil, startErr
	}
	return waitForReadyDaemon(ctx, socketPath, time.Now().Add(daemonStartTimeout))
}

func waitForReadyDaemon(ctx context.Context, socketPath string, deadline time.Time) (*bridgeExecutor, error) {
	var lastErr error
	for {
		client, err := bridge.Connect(ctx, socketPath)
		if err == nil {
			return readyBridgeExecutor(ctx, client)
		}
		lastErr = err
		if errors.Is(err, bridge.ErrVersionMismatch) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("wait for ssh-mcp daemon: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func startConfiguredDaemon(ctx context.Context, options RuntimeOptions) error {
	if options.daemonStarter != nil {
		return options.daemonStarter(ctx)
	}
	return startDaemonProcess(ctx)
}

func readyBridgeExecutor(ctx context.Context, client *bridge.Client) (*bridgeExecutor, error) {
	executor := newBridgeExecutor(client)
	status, err := executor.Status(ctx)
	if err == nil && status.Running {
		return executor, nil
	}
	_ = executor.Close(context.Background())
	if err != nil {
		return nil, fmt.Errorf("verify ssh-mcp daemon readiness: %w", err)
	}
	return nil, errors.New("ssh-mcp daemon is not ready")
}

func resolveRoots(options RuntimeOptions) (paths.Roots, error) {
	if options.Roots.ConfigDir != "" && options.Roots.RuntimeDir != "" {
		return options.Roots, nil
	}
	return paths.Default()
}

func RunManage(ctx context.Context) error {
	return runManage(ctx, RuntimeOptions{})
}

func Status(ctx context.Context) (DaemonStatus, error) {
	return daemonStatus(ctx, RuntimeOptions{})
}

func daemonStatus(ctx context.Context, options RuntimeOptions) (DaemonStatus, error) {
	roots, err := resolveRoots(options)
	if err != nil {
		return DaemonStatus{}, err
	}
	socketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	client, err := bridge.Connect(ctx, socketPath)
	if err != nil {
		if daemonPIDMissing(filepath.Join(roots.RuntimeDir, daemonPIDName)) {
			return DaemonStatus{Running: false}, nil
		}
		return DaemonStatus{}, fmt.Errorf("connect to ssh-mcp daemon: %w", err)
	}
	executor := newBridgeExecutor(client)
	defer executor.Close(context.Background())
	return executor.Status(ctx)
}

func Stop(ctx context.Context, force bool) error {
	return stopDaemon(ctx, RuntimeOptions{}, force)
}

func stopDaemon(ctx context.Context, options RuntimeOptions, force bool) error {
	roots, err := resolveRoots(options)
	if err != nil {
		return err
	}
	socketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	client, err := bridge.Connect(ctx, socketPath)
	if err != nil {
		if daemonPIDMissing(filepath.Join(roots.RuntimeDir, daemonPIDName)) {
			return ErrDaemonNotRunning
		}
		return fmt.Errorf("connect to ssh-mcp daemon: %w", err)
	}
	executor := newBridgeExecutor(client)
	pidPath := filepath.Join(roots.RuntimeDir, daemonPIDName)
	marker, err := readDaemonPID(pidPath)
	if err != nil {
		_ = executor.Close(context.Background())
		return fmt.Errorf("read ssh-mcp daemon PID marker: %w", err)
	}
	if err := prepareDaemonStop(ctx, executor, force); err != nil && !force {
		return err
	}
	deadline := time.Now().Add(daemonStopTimeout)
	for {
		exited, processErr := daemonProcessExitedMarker(marker)
		if processErr != nil {
			return processErr
		}
		if exited {
			return nil
		}
		if force && time.Now().After(deadline) {
			if err := forceStopDaemonMarker(marker); err != nil {
				return err
			}
			exited, processErr := waitForDaemonProcessExit(
				ctx,
				marker,
				time.Now().Add(daemonStopTimeout),
				daemonStopPollInterval,
				daemonProcessExitedMarker,
			)
			if processErr != nil {
				return processErr
			}
			if exited {
				return cleanupStoppedDaemon(roots, socketPath, pidPath, marker)
			}
			return errors.New("ssh-mcp daemon did not stop after forced termination")
		}
		if time.Now().After(deadline) {
			return errors.New("ssh-mcp daemon did not stop in time")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(daemonStopPollInterval):
		}
	}
}

// waitForDaemonProcessExit keeps checking after a termination request because
// both Unix signals and Windows process termination are asynchronous.
func waitForDaemonProcessExit(
	ctx context.Context,
	marker daemonPIDMarker,
	deadline time.Time,
	pollInterval time.Duration,
	check func(daemonPIDMarker) (bool, error),
) (bool, error) {
	if pollInterval <= 0 {
		return false, errors.New("daemon process exit poll interval must be positive")
	}
	for {
		exited, err := check(marker)
		if err != nil || exited {
			return exited, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		wait := pollInterval
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// cleanupStoppedDaemon serializes stale-artifact cleanup with daemon startup.
// A new daemon acquires this lock before publishing its endpoint and marker;
// when that happens, the stop request must leave the new daemon's artifacts
// untouched.
func cleanupStoppedDaemon(roots paths.Roots, socketPath, pidPath string, expected daemonPIDMarker) (result error) {
	lock, err := instance.Acquire(filepath.Join(roots.ConfigDir, instanceLockName))
	if errors.Is(err, instance.ErrAlreadyRunning) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("acquire ssh-mcp instance lock for cleanup: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			result = errors.Join(result, fmt.Errorf("release ssh-mcp instance lock after cleanup: %w", closeErr))
		}
	}()
	return cleanupStoppedDaemonArtifacts(socketPath, pidPath, expected)
}

// prepareDaemonStop 在撤销 bridge capability 前完成强停预备，以便 daemon 能封闭派发并记录未知结果。
func prepareDaemonStop(ctx context.Context, executor daemonStopExecutor, force bool) error {
	status, statusErr := executor.Status(ctx)
	if statusErr != nil {
		_ = executor.Close(context.Background())
		return statusErr
	}
	if status.ActiveBridgeSessions > 0 && !force {
		if err := executor.Close(context.Background()); err != nil {
			return err
		}
		return ErrDaemonBusy
	}
	if force {
		// 强停记录属于尽力操作，但必须在 capability 仍有效时发出。
		prepareContext, cancel := context.WithTimeout(context.Background(), bridgeResponseGrace)
		_ = executor.PrepareForceStop(prepareContext)
		cancel()
	}
	shutdownErr := executor.Shutdown(ctx)
	closeErr := executor.Close(context.Background())
	if shutdownErr != nil {
		return shutdownErr
	}
	// The shutdown response has already authorized and acknowledged the stop.
	// The daemon can close its bridge endpoint before this optional capability
	// cleanup round trip completes, so it must not turn a successful stop into
	// a client-visible failure.
	_ = closeErr
	return nil
}

func runManage(ctx context.Context, options RuntimeOptions) error {
	return runManageWithDesktopEnvironment(ctx, options, desktopEnvironmentFromOS(os.Getenv))
}

func runManageWithDesktopEnvironment(ctx context.Context, options RuntimeOptions, environment desktopEnvironment) error {
	executor, err := connectOrStartDaemon(ctx, options)
	if err != nil {
		return err
	}
	defer executor.Close(context.Background())
	waitContext, cancel := context.WithTimeout(ctx, tuiConnectTimeout+bridgeResponseGrace)
	defer cancel()
	return executor.OpenTUI(waitContext, environment)
}

func formatDaemonPID(marker daemonPIDMarker) string {
	return fmt.Sprintf("%s %d %d\n", daemonPIDMarkerVersion, marker.PID, marker.StartTime)
}

func parseDaemonPID(data []byte) (daemonPIDMarker, error) {
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != daemonPIDMarkerVersion {
		return daemonPIDMarker{}, errDaemonPIDMarker
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid <= 1 {
		return daemonPIDMarker{}, errDaemonPIDMarker
	}
	startTime, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || startTime == 0 {
		return daemonPIDMarker{}, errDaemonPIDMarker
	}
	return daemonPIDMarker{PID: pid, StartTime: startTime}, nil
}

func readDaemonPID(path string) (daemonPIDMarker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return daemonPIDMarker{}, err
	}
	marker, err := parseDaemonPID(data)
	if err != nil {
		return daemonPIDMarker{}, fmt.Errorf("read daemon PID: %w", err)
	}
	return marker, nil
}

func daemonPIDMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// reportDaemonStartup is also used by the pipe contract test. Windows does
// not launch through ExtraFiles, but keeping this helper functional there
// avoids a platform-specific test-only deadlock and permits future launchers
// to opt into the same readiness protocol.
func reportDaemonStartup(startupErr error) {
	fdText := os.Getenv(daemonStartupFDEnv)
	if fdText == "" {
		return
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < daemonStartupChildFD {
		return
	}
	file := os.NewFile(uintptr(fd), "ssh-mcp-daemon-startup")
	if file == nil {
		return
	}
	defer file.Close()
	if startupErr == nil {
		_, _ = fmt.Fprint(file, daemonStartupReady)
		return
	}
	message := strings.ReplaceAll(startupErr.Error(), "\n", " ")
	_, _ = fmt.Fprint(file, daemonStartupError+message)
}

func waitForDaemonStartup(ctx context.Context, reader *os.File) error {
	result := make(chan struct {
		message string
		err     error
	}, 1)
	go func() {
		data, err := io.ReadAll(reader)
		result <- struct {
			message string
			err     error
		}{message: strings.TrimSpace(string(data)), err: err}
	}()
	select {
	case <-ctx.Done():
		_ = reader.Close()
		<-result
		return fmt.Errorf("wait for ssh-mcp daemon startup: %w", ctx.Err())
	case value := <-result:
		if value.err != nil {
			return fmt.Errorf("read ssh-mcp daemon startup: %w", value.err)
		}
		if value.message == daemonStartupReady {
			return nil
		}
		if strings.HasPrefix(value.message, daemonStartupError) {
			return fmt.Errorf("ssh-mcp daemon startup failed: %s", strings.TrimSpace(strings.TrimPrefix(value.message, daemonStartupError)))
		}
		if value.message == "" {
			return errors.New("ssh-mcp daemon exited before reporting readiness")
		}
		return fmt.Errorf("invalid ssh-mcp daemon startup response %q", value.message)
	}
}
