//go:build linux

package app

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/instance"
	"ssh-mcp/internal/paths"
)

func TestDaemonPIDMarkerRequiresVersionedProcessIdentity(t *testing.T) {
	t.Parallel()

	valid := daemonPIDMarker{PID: os.Getpid(), StartTime: 12345}
	parsed, err := parseDaemonPID([]byte(formatDaemonPID(valid)))
	if err != nil {
		t.Fatalf("parseDaemonPID(valid) error = %v", err)
	}
	if parsed != valid {
		t.Fatalf("parseDaemonPID(valid) = %#v, want %#v", parsed, valid)
	}

	for _, invalid := range [][]byte{
		[]byte("1234\n"), // Legacy PID-only markers cannot identify a reused PID.
		[]byte("ssh-mcp-daemon-v1 1234\n"),
		[]byte("ssh-mcp-daemon-v1 1 12345\n"),
		[]byte("ssh-mcp-daemon-v1 1234 0\n"),
		[]byte("ssh-mcp-daemon-v1 1234 not-a-time\n"),
	} {
		if _, err := parseDaemonPID(invalid); !errors.Is(err, errDaemonPIDMarker) {
			t.Fatalf("parseDaemonPID(%q) error = %v, want errDaemonPIDMarker", invalid, err)
		}
	}
}

func TestDaemonProcessOperationsRejectMismatchedMarker(t *testing.T) {
	t.Parallel()

	startTime, err := bridge.ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessStartTime() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "daemon.pid")
	marker := daemonPIDMarker{PID: os.Getpid(), StartTime: startTime + 1}
	if err := os.WriteFile(path, []byte(formatDaemonPID(marker)), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	exited, err := daemonProcessExited(path)
	if exited || !errors.Is(err, errDaemonPIDMismatch) {
		t.Fatalf("daemonProcessExited() = (%t, %v), want (false, errDaemonPIDMismatch)", exited, err)
	}
	if err := forceStopDaemonProcess(path); !errors.Is(err, errDaemonPIDMismatch) {
		t.Fatalf("forceStopDaemonProcess() error = %v, want errDaemonPIDMismatch", err)
	}

	// Reaching this point proves the mismatched marker did not signal the test
	// process, which is the PID-reuse failure mode this guard prevents.
	if _, err := bridge.ProcessStartTime(os.Getpid()); err != nil {
		t.Fatalf("test process was not left running: %v", err)
	}
}

func TestDaemonProcessOperationsRejectMalformedMarker(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := os.WriteFile(path, []byte("99999\n"), 0o600); err != nil {
		t.Fatalf("write legacy marker: %v", err)
	}

	exited, err := daemonProcessExited(path)
	if exited || !errors.Is(err, errDaemonPIDMarker) {
		t.Fatalf("daemonProcessExited() = (%t, %v), want (false, errDaemonPIDMarker)", exited, err)
	}
	if err := forceStopDaemonProcess(path); !errors.Is(err, errDaemonPIDMarker) {
		t.Fatalf("forceStopDaemonProcess() error = %v, want errDaemonPIDMarker", err)
	}
}

func TestDaemonProcessExitedAcceptsMatchingCurrentMarker(t *testing.T) {
	t.Parallel()

	startTime, err := bridge.ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessStartTime() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "daemon.pid")
	marker := daemonPIDMarker{PID: os.Getpid(), StartTime: startTime}
	if err := os.WriteFile(path, []byte(formatDaemonPID(marker)), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	exited, err := daemonProcessExited(path)
	if err != nil || exited {
		t.Fatalf("daemonProcessExited() = (%t, %v), want (false, nil)", exited, err)
	}
}

func TestWriteDaemonPIDUsesProcessIdentityAndOnlyRemovesItsOwnMarker(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "daemon.pid")
	marker, err := writeDaemonPID(path, os.Getpid())
	if err != nil {
		t.Fatalf("writeDaemonPID() error = %v", err)
	}
	stored, err := readDaemonPID(path)
	if err != nil {
		t.Fatalf("readDaemonPID() error = %v", err)
	}
	if stored != marker || stored.PID != os.Getpid() || stored.StartTime == 0 {
		t.Fatalf("stored marker = %#v, want %#v", stored, marker)
	}

	newer := marker
	newer.StartTime++
	if err := os.WriteFile(path, []byte(formatDaemonPID(newer)), 0o600); err != nil {
		t.Fatalf("replace marker: %v", err)
	}
	if err := removeDaemonPID(path, marker); err != nil {
		t.Fatalf("removeDaemonPID(mismatched) error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("removeDaemonPID(mismatched) removed marker: %v", err)
	}
}

func TestCleanupStoppedDaemonDoesNotRemoveNewDaemonArtifactsWhileLockHeld(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	pidPath := filepath.Join(roots.RuntimeDir, daemonPIDName)
	newMarker := daemonPIDMarker{PID: 4321, StartTime: 9876}
	if err := os.WriteFile(pidPath, []byte(formatDaemonPID(newMarker)), 0o600); err != nil {
		t.Fatalf("write new daemon marker: %v", err)
	}
	socketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("sandbox does not permit Unix socket setup: %v", err)
		}
		t.Fatalf("listen new daemon endpoint: %v", err)
	}
	defer listener.Close()

	newDaemonLock, err := instance.Acquire(filepath.Join(roots.ConfigDir, instanceLockName))
	if err != nil {
		t.Fatalf("acquire new daemon instance lock: %v", err)
	}
	defer newDaemonLock.Close()

	oldMarker := daemonPIDMarker{PID: 1234, StartTime: 5678}
	if err := cleanupStoppedDaemon(roots, socketPath, pidPath, oldMarker); err != nil {
		t.Fatalf("cleanupStoppedDaemon() error = %v", err)
	}
	stored, err := readDaemonPID(pidPath)
	if err != nil {
		t.Fatalf("read new daemon marker after cleanup: %v", err)
	}
	if stored != newMarker {
		t.Fatalf("stored daemon marker = %#v, want %#v", stored, newMarker)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("stat new daemon endpoint after cleanup: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("new daemon endpoint mode = %v, want socket", info.Mode())
	}
}

func TestCleanupStoppedDaemonOnlyRemovesMatchingMarker(t *testing.T) {
	base := t.TempDir()
	roots, err := paths.Prepare(filepath.Join(base, "config"), filepath.Join(base, "runtime"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	pidPath := filepath.Join(roots.RuntimeDir, daemonPIDName)
	newMarker := daemonPIDMarker{PID: 4321, StartTime: 9876}
	if err := os.WriteFile(pidPath, []byte(formatDaemonPID(newMarker)), 0o600); err != nil {
		t.Fatalf("write new daemon marker: %v", err)
	}

	oldMarker := daemonPIDMarker{PID: 1234, StartTime: 5678}
	if err := cleanupStoppedDaemon(roots, filepath.Join(roots.RuntimeDir, bridgeSockName), pidPath, oldMarker); err != nil {
		t.Fatalf("cleanupStoppedDaemon() error = %v", err)
	}
	stored, err := readDaemonPID(pidPath)
	if err != nil {
		t.Fatalf("read newer marker after cleanup: %v", err)
	}
	if stored != newMarker {
		t.Fatalf("stored marker = %#v, want %#v", stored, newMarker)
	}
}
