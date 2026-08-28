// Package bridge implements the private daemon execution channel used by
// short-lived MCP stdio bridge processes. It is intentionally separate from
// the TUI control channel: a bridge capability cannot call control methods.
package bridge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/unixtransport"
)

const (
	ProtocolVersion   = 1
	defaultSessionTTL = 15 * time.Second
)

var (
	ErrUnauthorized         = errors.New("bridge request is not authorized")
	ErrMethodNotFound       = errors.New("bridge method was not found")
	ErrInvalidRequest       = errors.New("invalid bridge request")
	ErrServerNotStarted     = errors.New("bridge server is not started")
	ErrVersionMismatch      = errors.New("bridge protocol version is not compatible")
	ErrTUIConnectionTimeout = errors.New("local TUI did not connect before the deadline")
)

type Session struct {
	ID               string
	PID              int
	ProcessStartTime uint64
	OwnerID          string
	WorkingDirectory string
	CreatedAt        time.Time
}

type Handler interface {
	Handle(context.Context, Session, string, json.RawMessage) (any, error)
}

type HandlerFunc func(context.Context, Session, string, json.RawMessage) (any, error)

func (f HandlerFunc) Handle(ctx context.Context, session Session, method string, params json.RawMessage) (any, error) {
	return f(ctx, session, method, params)
}

type ServerOptions struct {
	SocketPath    string
	Handler       Handler
	UID           int
	SessionTTL    time.Duration
	SessionOpened func(Session)
	// SessionClosed 在某个主体的最后一个 capability 已撤销且不持有 Server 锁时调用。
	// 它提供 Runtime 所需的主体身份，但单个短连接关闭不等同于主体进程退出。
	SessionClosed func(Session)
}

type Server struct {
	socketPath    string
	handler       Handler
	sessionTTL    time.Duration
	sessionOpened func(Session)
	sessionClosed func(Session)

	mu            sync.Mutex
	closed        bool
	sessions      map[string]serverSession
	owners        map[string]int
	transport     *unixtransport.Server
	monitorCancel context.CancelFunc
	monitorDone   chan struct{}
}

type serverSession struct {
	Session
	token        []byte
	lastActivity time.Time
}

type request struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation"`
	SessionID string          `json:"session_id,omitempty"`
	Token     string          `json:"token,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
}

type response struct {
	SessionID string          `json:"session_id,omitempty"`
	Token     string          `json:"token,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *responseError  `json:"error,omitempty"`
}

type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewServer(options ServerOptions) *Server {
	ttl := options.SessionTTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	server := &Server{
		socketPath:    options.SocketPath,
		handler:       options.Handler,
		sessionTTL:    ttl,
		sessionOpened: options.SessionOpened,
		sessionClosed: options.SessionClosed,
		sessions:      make(map[string]serverSession),
		owners:        make(map[string]int),
	}
	server.transport = unixtransport.NewServer(unixtransport.ServerOptions{
		SocketPath:    options.SocketPath,
		ExpectedUID:   options.UID,
		Handler:       server.handleTransportRequest,
		EncodeFailure: server.encodeTransportFailure,
	})
	return server
}

func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) Start() error {
	if s.socketPath == "" || s.handler == nil {
		return ErrInvalidRequest
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrInvalidRequest
	}
	if err := s.transport.Start(); err != nil {
		s.mu.Unlock()
		if errors.Is(err, unixtransport.ErrInvalidServer) {
			return ErrInvalidRequest
		}
		return fmt.Errorf("start bridge local transport: %w", err)
	}
	if s.monitorCancel == nil {
		monitorContext, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		s.monitorCancel = cancel
		s.monitorDone = done
		go s.monitorOwners(monitorContext, done)
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	monitorCancel := s.monitorCancel
	monitorDone := s.monitorDone
	s.monitorCancel = nil
	s.monitorDone = nil
	sessions := s.sessions
	s.sessions = make(map[string]serverSession)
	owners := make(map[string]Session, len(s.owners))
	for _, session := range sessions {
		owners[session.OwnerID] = session.Session
	}
	s.owners = make(map[string]int)
	s.mu.Unlock()
	if monitorCancel != nil {
		monitorCancel()
		if monitorDone != nil {
			<-monitorDone
		}
	}
	for _, session := range owners {
		s.notifyClosed(session)
	}
	return s.transport.Close()
}

func (s *Server) ActiveSessions() int {
	s.expireSessions(clock.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// monitorOwners 主动检测已停止的 bridge 进程，避免只有新的控制请求到来时才清理主体状态。
func (s *Server) monitorOwners(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	interval := s.sessionTTL / 2
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.expireSessions(now)
		}
	}
}

func (s *Server) handleTransportRequest(transportRequest unixtransport.Request) json.RawMessage {
	var request request
	if err := json.Unmarshal(transportRequest.Message, &request); err != nil {
		return s.encodeResponse(response{Error: newResponseError(ErrInvalidRequest)})
	}
	if request.Version != ProtocolVersion {
		return s.encodeResponse(response{Error: newResponseError(ErrVersionMismatch)})
	}
	switch request.Operation {
	case "open":
		return s.encodeResponse(s.handleOpen(transportRequest.Peer))
	case "close":
		return s.encodeResponse(s.handleClose(request))
	case "call":
		return s.encodeResponse(s.handleCall(transportRequest.Context, request))
	default:
		return s.encodeResponse(response{Error: newResponseError(ErrInvalidRequest)})
	}
}

func (s *Server) encodeTransportFailure(failure unixtransport.Failure) json.RawMessage {
	if failure == unixtransport.FailureUnauthorizedPeer {
		return s.encodeResponse(response{Error: newResponseError(ErrUnauthorized)})
	}
	return s.encodeResponse(response{Error: newResponseError(ErrInvalidRequest)})
}

func (s *Server) encodeResponse(output response) json.RawMessage {
	encoded, err := json.Marshal(output)
	if err != nil {
		return json.RawMessage(`{"error":{"code":"invalid_request","message":"invalid bridge request"}}`)
	}
	return encoded
}

func (s *Server) handleOpen(peer unixtransport.Peer) response {
	sessionID, err := newCapability()
	if err != nil {
		return response{Error: newResponseError(err)}
	}
	token, err := newCapability()
	if err != nil {
		return response{Error: newResponseError(err)}
	}
	now := clock.Now()
	startedAt, err := processStartTime(peer.PID)
	if err != nil {
		return response{Error: newResponseError(ErrUnauthorized)}
	}
	session := serverSession{
		Session: Session{ID: sessionID, PID: peer.PID, ProcessStartTime: startedAt, OwnerID: fmt.Sprintf("pid:%d:start:%d", peer.PID, startedAt), WorkingDirectory: processWorkingDirectory(peer.PID), CreatedAt: now},
		token:   []byte(token), lastActivity: now,
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return response{Error: newResponseError(ErrServerNotStarted)}
	}
	s.sessions[sessionID] = session
	s.owners[session.OwnerID]++
	s.mu.Unlock()
	s.notifyOpened(session.Session)
	return response{SessionID: sessionID, Token: token}
}

func (s *Server) handleClose(request request) response {
	session, lastForOwner, ok := s.removeSession(request.SessionID, request.Token)
	if !ok {
		return response{Error: newResponseError(ErrUnauthorized)}
	}
	if lastForOwner {
		s.notifyClosed(session)
	}
	return response{}
}

func (s *Server) handleCall(ctx context.Context, request request) response {
	if request.Method == "" {
		return response{Error: newResponseError(ErrInvalidRequest)}
	}
	session, ok := s.authorizedSession(request.SessionID, request.Token)
	if !ok {
		return response{Error: newResponseError(ErrUnauthorized)}
	}
	if request.Method == "bridge.heartbeat" {
		return response{}
	}
	result, err := s.handler.Handle(ctx, session.Session, request.Method, request.Params)
	if err != nil {
		return response{Error: newResponseError(err)}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return response{Error: newResponseError(ErrInvalidRequest)}
	}
	return response{Result: encoded}
}

func (s *Server) authorizedSession(id, token string) (serverSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || subtle.ConstantTimeCompare([]byte(token), session.token) != 1 {
		return serverSession{}, false
	}
	session.lastActivity = clock.Now()
	s.sessions[id] = session
	return session, true
}

func (s *Server) removeSession(id, token string) (Session, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || subtle.ConstantTimeCompare([]byte(token), session.token) != 1 {
		return Session{}, false, false
	}
	delete(s.sessions, id)
	return session.Session, s.releaseOwnerLocked(session.OwnerID), true
}

func (s *Server) expireSessions(now time.Time) {
	var expired []Session
	s.mu.Lock()
	for id, session := range s.sessions {
		if now.Sub(session.lastActivity) <= s.sessionTTL {
			continue
		}
		if sessionOwnerAlive(session.Session) {
			// 主体仍存在时 capability 归属于该进程，而不是某一次短连接。
			session.lastActivity = now
			s.sessions[id] = session
			continue
		}
		delete(s.sessions, id)
		if s.releaseOwnerLocked(session.OwnerID) {
			expired = append(expired, session.Session)
		}
	}
	s.mu.Unlock()
	for _, session := range expired {
		s.notifyClosed(session)
	}
}

// releaseOwnerLocked 返回该 capability 是否为主体的最后一个 capability。
// 调用方必须已持有 Server 锁。
func (s *Server) releaseOwnerLocked(ownerID string) bool {
	remaining := s.owners[ownerID]
	if remaining <= 1 {
		delete(s.owners, ownerID)
		return true
	}
	s.owners[ownerID] = remaining - 1
	return false
}

func sessionOwnerAlive(session Session) bool {
	startedAt, err := processStartTime(session.PID)
	return err == nil && startedAt == session.ProcessStartTime
}

func (s *Server) notifyOpened(session Session) {
	s.mu.Lock()
	callback := s.sessionOpened
	s.mu.Unlock()
	if callback != nil {
		callback(session)
	}
}

func (s *Server) notifyClosed(session Session) {
	s.mu.Lock()
	callback := s.sessionClosed
	s.mu.Unlock()
	if callback != nil {
		callback(session)
	}
}

type Client struct {
	socketPath string
	sessionID  string
	token      string
}

func Connect(ctx context.Context, socketPath string) (*Client, error) {
	opened, err := roundTrip(ctx, socketPath, request{Version: ProtocolVersion, Operation: "open"})
	if err != nil {
		return nil, err
	}
	if opened.SessionID == "" || opened.Token == "" {
		return nil, ErrInvalidRequest
	}
	return &Client{socketPath: socketPath, sessionID: opened.SessionID, token: opened.Token}, nil
}

func (c *Client) SessionID() string {
	if c == nil {
		return ""
	}
	return c.sessionID
}

func (c *Client) Call(ctx context.Context, method string, params any, result any) error {
	if c == nil || method == "" {
		return ErrInvalidRequest
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode bridge parameters: %w", err)
	}
	return call(ctx, c.socketPath, request{Version: ProtocolVersion, Operation: "call", SessionID: c.sessionID, Token: c.token, Method: method, Params: encoded}, result)
}

func (c *Client) Heartbeat(ctx context.Context) error {
	if c == nil {
		return ErrInvalidRequest
	}
	return call(ctx, c.socketPath, request{Version: ProtocolVersion, Operation: "call", SessionID: c.sessionID, Token: c.token, Method: "bridge.heartbeat", Params: json.RawMessage("{}")}, nil)
}

func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.sessionID == "" {
		return nil
	}
	err := call(ctx, c.socketPath, request{Version: ProtocolVersion, Operation: "close", SessionID: c.sessionID, Token: c.token}, nil)
	c.sessionID = ""
	c.token = ""
	return err
}

func call(ctx context.Context, socketPath string, request request, result any) error {
	response, err := roundTrip(ctx, socketPath, request)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode bridge result: %w", err)
	}
	return nil
}

func roundTrip(ctx context.Context, socketPath string, request request) (response, error) {
	connection, err := unixtransport.Dial(ctx, socketPath)
	if err != nil {
		return response{}, fmt.Errorf("connect to local bridge: %w", err)
	}
	defer connection.Close()
	requestDone := make(chan struct{})
	defer close(requestDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-requestDone:
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return response{}, fmt.Errorf("set bridge deadline: %w", err)
		}
	}
	if err := unixtransport.Encode(connection, request); err != nil {
		if ctx.Err() != nil {
			return response{}, ctx.Err()
		}
		return response{}, fmt.Errorf("write bridge request: %w", err)
	}
	var output response
	if err := unixtransport.Decode(connection, &output); err != nil {
		if ctx.Err() != nil {
			return response{}, ctx.Err()
		}
		return response{}, fmt.Errorf("read bridge response: %w", err)
	}
	if output.Error != nil {
		return response{}, errorFromResponse(output.Error)
	}
	return output, nil
}

func newCapability() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate bridge capability: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func newResponseError(err error) *responseError {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return &responseError{Code: "unauthorized", Message: "bridge request was rejected"}
	case errors.Is(err, ErrMethodNotFound):
		return &responseError{Code: "method_not_found", Message: "bridge method was not found"}
	case errors.Is(err, ErrVersionMismatch):
		return &responseError{Code: "version_mismatch", Message: "bridge protocol is not compatible"}
	case errors.Is(err, ErrInvalidRequest):
		return &responseError{Code: "invalid_request", Message: "invalid bridge request"}
	case errors.Is(err, ErrTUIConnectionTimeout):
		return &responseError{Code: "tui_connection_timeout", Message: ErrTUIConnectionTimeout.Error()}
	default:
		return &responseError{Code: "operation_failed", Message: "bridge operation failed"}
	}
}

func errorFromResponse(response *responseError) error {
	switch response.Code {
	case "unauthorized":
		return ErrUnauthorized
	case "method_not_found":
		return ErrMethodNotFound
	case "version_mismatch":
		return ErrVersionMismatch
	case "invalid_request":
		return ErrInvalidRequest
	case "tui_connection_timeout":
		return ErrTUIConnectionTimeout
	default:
		return errors.New(response.Message)
	}
}
