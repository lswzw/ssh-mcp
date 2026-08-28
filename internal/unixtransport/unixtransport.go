// Package unixtransport provides the authenticated local short-connection
// transport shared by bridge and IPC. The historical package name is kept for
// compatibility; the implementation uses Unix sockets on Unix and named pipes
// on Windows.
package unixtransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const MaxMessageSize = 1 << 20

var ErrInvalidServer = errors.New("本地 Unix 传输服务配置无效")

type Peer struct {
	UID int
	PID int
	// Identity is an optional platform-native identifier (for example a
	// Windows user SID). UID remains populated on Unix for compatibility.
	Identity string
}

type Request struct {
	Context context.Context
	Peer    Peer
	Message json.RawMessage
}

type Handler func(Request) json.RawMessage

type Failure uint8

const (
	FailureUnauthorizedPeer Failure = iota + 1
	FailureInvalidMessage
)

type FailureEncoder func(Failure) json.RawMessage

type ServerOptions struct {
	SocketPath    string
	ExpectedUID   int
	Handler       Handler
	EncodeFailure FailureEncoder
}

type Server struct {
	socketPath    string
	expectedUID   int
	handler       Handler
	encodeFailure FailureEncoder

	mu           sync.Mutex
	listener     net.Listener
	endpointLock endpointLock
	closed       bool
}

type endpointLock interface {
	Close() error
}

func NewServer(options ServerOptions) *Server {
	expectedUID := options.ExpectedUID
	if expectedUID == 0 {
		expectedUID = defaultPeerUID()
	}
	return &Server{
		socketPath:    options.SocketPath,
		expectedUID:   expectedUID,
		handler:       options.Handler,
		encodeFailure: options.EncodeFailure,
	}
}

func (s *Server) Start() error {
	if s == nil || s.socketPath == "" || s.handler == nil || s.encodeFailure == nil {
		return ErrInvalidServer
	}
	s.mu.Lock()
	if s.closed || s.listener != nil {
		s.mu.Unlock()
		return ErrInvalidServer
	}
	lock, err := acquireLocalEndpointLock(s.socketPath)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("lock local transport endpoint: %w", err)
	}
	if err := prepareLocalEndpoint(s.socketPath); err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		s.mu.Unlock()
		return err
	}
	listener, err := listenLocal(s.socketPath)
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		s.mu.Unlock()
		return fmt.Errorf("listen local transport: %w", err)
	}
	s.listener = listener
	s.endpointLock = lock
	s.mu.Unlock()
	go s.acceptLoop(listener)
	return nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	s.listener = nil
	lock := s.endpointLock
	s.endpointLock = nil
	s.mu.Unlock()
	var result error
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		if err := removeLocalEndpoint(s.socketPath); err != nil {
			result = errors.Join(result, err)
		}
	}
	if lock != nil {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *Server) acceptLoop(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A failed pipe-instance creation is permanent for this listener; do
			// not turn it into a busy loop. Keep retrying only errors that the
			// listener explicitly reports as temporary.
			var temporary interface{ Temporary() bool }
			if !errors.As(err, &temporary) || !temporary.Temporary() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.handleConnection(connection)
	}
}

func (s *Server) handleConnection(connection net.Conn) {
	defer connection.Close()
	s.mu.Lock()
	expectedUID := s.expectedUID
	handler := s.handler
	encodeFailure := s.encodeFailure
	s.mu.Unlock()
	peer, err := peerCredentials(connection)
	if err != nil || !peerMatches(peer, expectedUID) {
		writeFailure(connection, encodeFailure, FailureUnauthorizedPeer)
		return
	}
	var message json.RawMessage
	if err := Decode(connection, &message); err != nil {
		writeFailure(connection, encodeFailure, FailureInvalidMessage)
		return
	}
	ctx, cancel := connectionContext(connection)
	defer cancel()
	_ = Encode(connection, handler(Request{Context: ctx, Peer: peer, Message: message}))
}

func writeFailure(connection net.Conn, encodeFailure FailureEncoder, failure Failure) {
	if encodeFailure == nil {
		return
	}
	_ = Encode(connection, encodeFailure(failure))
}

func Decode(reader io.Reader, value any) error {
	return json.NewDecoder(io.LimitReader(reader, MaxMessageSize)).Decode(value)
}

func Encode(writer io.Writer, value any) error {
	return json.NewEncoder(writer).Encode(value)
}

// Dial connects to the platform-local endpoint selected by the server. It is
// intentionally exported so bridge and IPC clients cannot accidentally bypass
// the Windows named-pipe transport with a hard-coded Unix network name.
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	if endpoint == "" {
		return nil, errors.New("local transport endpoint is empty")
	}
	return dialLocal(ctx, endpoint)
}

func connectionContext(connection net.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		buffer := make([]byte, 1)
		_, _ = connection.Read(buffer)
		cancel()
	}()
	return ctx, cancel
}
