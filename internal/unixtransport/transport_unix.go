//go:build !windows

package unixtransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"ssh-mcp/internal/instance"
)

func defaultPeerUID() int { return os.Getuid() }

func peerMatches(peer Peer, expected int) bool { return peer.UID == expected }

func acquireLocalEndpointLock(path string) (endpointLock, error) {
	if err := ensureSocketDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := instance.Acquire(path + ".lock")
	if err != nil {
		return nil, err
	}
	return lock, nil
}

func prepareLocalEndpoint(path string) error {
	if err := ensureSocketDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return removeExistingSocket(path)
}

func listenLocal(path string) (net.Listener, error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func ensureSocketDirectory(path string) error {
	if err := os.MkdirAll(path, 0o777); err != nil {
		return fmt.Errorf("create local socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect local socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("local socket directory must be a real directory")
	}
	return nil
}

func removeExistingSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing local socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("local socket path exists and is not a socket")
	}
	// An endpoint can still have a live listener even though its directory
	// entry is removable. Probe it before unlinking so a second server cannot
	// silently take over an active control channel.
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("local socket path is already in use")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		return fmt.Errorf("probe existing local socket: %w", dialErr)
	}
	latest, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reinspect existing local socket: %w", err)
	}
	if latest.Mode()&os.ModeSocket == 0 {
		return errors.New("local socket path changed while probing")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale local socket: %w", err)
	}
	return nil
}

func removeLocalEndpoint(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect local socket for cleanup: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove local socket: %w", err)
	}
	return nil
}
