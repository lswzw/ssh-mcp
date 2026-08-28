//go:build windows

package unixtransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"ssh-mcp/internal/paths"
)

// Windows does not expose a numeric Unix UID. The named-pipe client identity
// comparison below provides the equivalent per-user authorization boundary.
func defaultPeerUID() int { return -1 }

func peerMatches(peer Peer, _ int) bool {
	identity, err := currentUserSID()
	return err == nil && identity != "" && peer.Identity == identity
}

// Named-pipe creation uses FILE_FLAG_FIRST_PIPE_INSTANCE as the endpoint
// ownership primitive, so no filesystem sidecar lock is needed on Windows.
func acquireLocalEndpointLock(string) (endpointLock, error) { return nil, nil }

func prepareLocalEndpoint(path string) error {
	directory := filepath.Dir(path)
	if err := paths.EnsureDirectory(directory); err != nil {
		return fmt.Errorf("create local transport directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect local transport directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("local transport directory must be a real directory")
	}
	// The endpoint is a named pipe, so no filesystem socket is created. Do
	// not silently reuse any filesystem object at the requested path: this
	// matches the Unix endpoint contract and prevents surprising aliases.
	if _, err := os.Lstat(path); err == nil {
		return errors.New("local transport path is occupied")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect local transport path: %w", err)
	}
	return nil
}

func listenLocal(path string) (net.Listener, error) {
	listener, err := newPipeListener(path)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	name := pipeName(path)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(
			windows.StringToUTF16Ptr(name),
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err == nil {
			return newPipeConn(handle, name), nil
		}
		// A busy pipe belongs to a live server and can become available shortly.
		// FILE_NOT_FOUND means no server instance exists; returning it lets the
		// caller start a daemon (or report it stopped) instead of spinning forever
		// when it uses a background context.
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("open local named pipe: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func removeLocalEndpoint(string) error { return nil }

func pipeName(path string) string {
	digest := sha256.Sum256([]byte(path))
	return `\\.\pipe\ssh-mcp-` + hex.EncodeToString(digest[:])
}

type pipeListener struct {
	name string

	mu           sync.Mutex
	closed       bool
	current      windows.Handle
	currentPipe  *pipeInstance
	currentToken uint64
	nextToken    uint64
	first        bool
}

type pipeInstance struct {
	handle  windows.Handle
	connect *windows.Overlapped
}

// temporaryPipeAcceptError tells Server.acceptLoop that a client disconnected
// while this pipe instance was being accepted. The listener can safely create
// a fresh instance and keep serving subsequent clients.
type temporaryPipeAcceptError struct {
	err error
}

func (e temporaryPipeAcceptError) Error() string   { return e.err.Error() }
func (e temporaryPipeAcceptError) Unwrap() error   { return e.err }
func (e temporaryPipeAcceptError) Temporary() bool { return true }

func pipeAcceptError(err error) error {
	wrapped := fmt.Errorf("accept local named pipe: %w", err)
	if isTemporaryPipeAcceptError(err) {
		return temporaryPipeAcceptError{err: wrapped}
	}
	return wrapped
}

func newPipeListener(path string) (*pipeListener, error) {
	listener := &pipeListener{name: pipeName(path), first: true}
	// Create the first instance before Server.Start succeeds. Besides giving
	// callers immediate startup errors, FILE_FLAG_FIRST_PIPE_INSTANCE proves
	// that another process has not already claimed this endpoint name.
	if err := listener.createInstanceLocked(); err != nil {
		return nil, err
	}
	return listener, nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	handle := l.current
	instance := l.currentPipe
	token := l.currentToken
	if handle == 0 {
		if err := l.createInstanceLocked(); err != nil {
			l.mu.Unlock()
			return nil, err
		}
		handle = l.current
		instance = l.currentPipe
		token = l.currentToken
	}
	if handle == 0 || instance == nil {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("create named-pipe accept event: %w", err)
	}
	overlapped := &windows.Overlapped{HEvent: event}
	instance.connect = overlapped
	handle = instance.handle
	// ConnectNamedPipe returns immediately for an overlapped handle, so the
	// lock can be held while publishing the operation to Close.
	err = windows.ConnectNamedPipe(handle, overlapped)
	l.mu.Unlock()
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		err = nil
	} else if errors.Is(err, windows.ERROR_IO_PENDING) {
		state, waitErr := windows.WaitForSingleObject(event, windows.INFINITE)
		if waitErr != nil {
			err = waitErr
		} else if state != windows.WAIT_OBJECT_0 {
			err = errors.New("wait for named-pipe connection failed")
		} else {
			var transferred uint32
			err = windows.GetOverlappedResult(handle, overlapped, &transferred, false)
		}
	}
	_ = windows.CloseHandle(event)
	owned, closed, nextErr := l.finishAccept(handle, token, err, l.createInstanceLocked)
	if err != nil {
		if owned {
			_ = windows.CloseHandle(instance.handle)
		}
		if closed {
			return nil, net.ErrClosed
		}
		if nextErr != nil {
			return nil, nextErr
		}
		return nil, pipeAcceptError(err)
	}
	if nextErr != nil {
		// Do not hand out a connected pipe when the listener cannot preserve
		// its accept capacity. The caller will observe the permanent listener
		// error, while the accepted handle is closed exactly once below.
		if owned {
			_ = windows.CloseHandle(instance.handle)
		}
		return nil, nextErr
	}
	if closed {
		if owned {
			_ = windows.CloseHandle(instance.handle)
		}
		return nil, net.ErrClosed
	}
	if !owned {
		return nil, net.ErrClosed
	}
	return newPipeConn(instance.handle, l.name), nil
}

// finishAccept transfers ownership of the connected handle away from the
// listener and replenishes the pending instance before Accept returns. The
// ownership bit is important when Close races a blocked ConnectNamedPipe:
// Close cancels the pending operation but leaves its handle for Accept to
// release, so a stale Accept cannot close a potentially reused handle value.
//
// createNext is injectable for platform-independent state tests. Production
// callers pass createInstanceLocked while holding l.mu.
func (l *pipeListener) finishAccept(handle windows.Handle, token uint64, acceptErr error, createNext func() error) (owned, closed bool, nextErr error) {
	l.mu.Lock()
	// Compare the generation as well as the numeric handle. Windows may reuse a
	// handle value immediately after CloseHandle; equality on the value alone
	// could make a blocked Accept close a newer instance it does not own.
	owned = l.current == handle && l.currentToken == token && token != 0
	if owned {
		l.current = 0
		instance := l.currentPipe
		l.currentPipe = nil
		l.currentToken = 0
		if instance != nil {
			instance.connect = nil
		}
	}
	closed = l.closed
	if owned && !closed && createNext != nil && (acceptErr == nil || isTemporaryPipeAcceptError(acceptErr)) {
		nextErr = createNext()
	}
	l.mu.Unlock()
	return owned, closed, nextErr
}

func isTemporaryPipeAcceptError(err error) bool {
	return errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_PIPE_LISTENING)
}

func (l *pipeListener) createInstanceLocked() error {
	flags := uint32(0)
	if l.first {
		flags = windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	flags |= windows.FILE_FLAG_OVERLAPPED
	handle, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(l.name),
		windows.PIPE_ACCESS_DUPLEX|flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES,
		MaxMessageSize,
		MaxMessageSize,
		0,
		nil,
	)
	if err != nil {
		return fmt.Errorf("create local named pipe: %w", err)
	}
	l.first = false
	l.current = handle
	l.currentPipe = &pipeInstance{handle: handle}
	l.nextToken++
	if l.nextToken == 0 {
		l.nextToken++
	}
	l.currentToken = l.nextToken
	return nil
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	handle := l.current
	instance := l.currentPipe
	if instance != nil && instance.connect == nil {
		l.current = 0
		l.currentPipe = nil
		l.currentToken = 0
	}
	l.mu.Unlock()
	if instance == nil {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil
	}
	if instance.connect != nil {
		if err := windows.CancelIoEx(instance.handle, instance.connect); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("cancel named-pipe accept: %w", err)
		}
		return nil
	}
	_ = windows.CloseHandle(instance.handle)
	return nil
}

type pipeConn struct {
	handle    windows.Handle
	name      string
	closeOnce sync.Once
}

func newPipeConn(handle windows.Handle, name string) *pipeConn {
	return &pipeConn{handle: handle, name: name}
}

func (c *pipeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	done, err := c.io(p, false)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return done, io.EOF
	}
	return done, err
}

func (c *pipeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.io(p, true)
}

func (c *pipeConn) io(p []byte, write bool) (int, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	var transferred uint32
	if write {
		err = windows.WriteFile(c.handle, p, &transferred, overlapped)
	} else {
		err = windows.ReadFile(c.handle, p, &transferred, overlapped)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		state, waitErr := windows.WaitForSingleObject(event, windows.INFINITE)
		if waitErr != nil {
			return 0, waitErr
		}
		if state != windows.WAIT_OBJECT_0 {
			return 0, errors.New("wait for named-pipe I/O failed")
		}
		err = windows.GetOverlappedResult(c.handle, overlapped, &transferred, false)
	}
	return int(transferred), err
}

func (c *pipeConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		if cancelErr := windows.CancelIoEx(c.handle, nil); cancelErr != nil && !errors.Is(cancelErr, windows.ERROR_NOT_FOUND) {
			err = cancelErr
		}
		if closeErr := windows.CloseHandle(c.handle); closeErr != nil && err == nil {
			err = closeErr
		}
	})
	return err
}
func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.name) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.name) }

// Context cancellation closes the connection in callers. Windows named pipe
// handles do not implement the netpoll deadline contract, so keep deadline
// calls harmless and rely on that close path for cancellation.
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr string

func (a pipeAddr) Network() string { return "namedpipe" }
func (a pipeAddr) String() string  { return string(a) }

func currentUserSID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("current process has no user SID")
	}
	value := user.User.Sid.String()
	if value == "" {
		return "", errors.New("current process SID is empty")
	}
	return value, nil
}

func peerCredentials(connection net.Conn) (Peer, error) {
	pipe, ok := connection.(*pipeConn)
	if !ok {
		return Peer{}, errors.New("local transport is not a named pipe")
	}
	handle := pipe.handle
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &pid); err != nil {
		return Peer{}, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		if err == nil {
			err = errors.New("peer process has no user SID")
		}
		return Peer{}, err
	}
	return Peer{UID: -1, PID: int(pid), Identity: user.User.Sid.String()}, nil
}
