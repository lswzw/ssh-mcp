// Package ipc provides the authenticated local control channel between the
// MCP process and its separately started TUI process.
package ipc

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

	"ssh-mcp/internal/unixtransport"
)

var (
	ErrUnauthorized                  = errors.New("local IPC request is not authorized")
	ErrMethodNotFound                = errors.New("local IPC method was not found")
	ErrInvalidRequest                = errors.New("invalid local IPC request")
	ErrServerNotStarted              = errors.New("local IPC server is not started")
	ErrLocked                        = errors.New("local credential store is locked")
	ErrCandidateNotDispatched        = errors.New("candidate validation was not dispatched")
	ErrCandidateAuditWriteFailed     = errors.New("candidate validation audit write failed")
	ErrConfirmationRequired          = errors.New("local confirmation is required")
	ErrCandidateConnectionFailed     = errors.New("candidate connection validation failed")
	ErrCandidateAuthenticationFailed = errors.New("candidate authentication validation failed")
	ErrCandidateTLSFailed            = errors.New("candidate TLS validation failed")
)

// Categorize marks a local-control error with a stable, sanitized category.
// The IPC response uses only that category and never serializes the cause,
// which may contain target details, driver output, or credential-adjacent text.
func Categorize(err, category error) error {
	if err == nil || category == nil || errors.Is(err, category) {
		return err
	}
	return categorizedError{category: category, cause: err}
}

type categorizedError struct {
	category error
	cause    error
}

func (e categorizedError) Error() string {
	return e.category.Error()
}

func (e categorizedError) Unwrap() error {
	return e.cause
}

func (e categorizedError) Is(target error) bool {
	return target == e.category
}

type Request struct {
	Token  string          `json:"token"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ResponseError  `json:"error,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Handler interface {
	Handle(context.Context, string, json.RawMessage) (any, error)
}

type HandlerFunc func(context.Context, string, json.RawMessage) (any, error)

func (f HandlerFunc) Handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	return f(ctx, method, params)
}

type ServerOptions struct {
	SocketPath string
	Token      string
	Handler    Handler
	UID        int
}

type Server struct {
	socketPath   string
	tokenMu      sync.RWMutex
	token        []byte
	requireToken bool
	handler      Handler
	transport    *unixtransport.Server
}

func NewServer(options ServerOptions) *Server {
	server := &Server{
		socketPath:   options.SocketPath,
		token:        []byte(options.Token),
		requireToken: options.Token != "",
		handler:      options.Handler,
	}
	server.transport = unixtransport.NewServer(unixtransport.ServerOptions{
		SocketPath:    options.SocketPath,
		ExpectedUID:   options.UID,
		Handler:       server.handleTransportRequest,
		EncodeFailure: server.encodeTransportFailure,
	})
	return server
}

func NewToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate IPC token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *Server) Start() error {
	if s.socketPath == "" || s.handler == nil {
		return ErrInvalidRequest
	}
	if err := s.transport.Start(); err != nil {
		if errors.Is(err, unixtransport.ErrInvalidServer) {
			return ErrInvalidRequest
		}
		return fmt.Errorf("start local IPC transport: %w", err)
	}
	return nil
}

func (s *Server) Close() error {
	return s.transport.Close()
}

// SetToken replaces the capability required for future control requests.
// A token is intentionally required once this method has been called, even if
// the server was initially created for same-user, tokenless use.
func (s *Server) SetToken(token string) error {
	if s == nil || token == "" {
		return ErrInvalidRequest
	}
	replacement := []byte(token)
	s.tokenMu.Lock()
	previous := s.token
	s.token = replacement
	s.requireToken = true
	s.tokenMu.Unlock()
	clear(previous)
	return nil
}

// DisableToken rejects every request until SetToken installs a new capability.
func (s *Server) DisableToken() {
	if s == nil {
		return
	}
	s.tokenMu.Lock()
	previous := s.token
	s.token = nil
	s.requireToken = true
	s.tokenMu.Unlock()
	clear(previous)
}

func (s *Server) tokenSnapshot() ([]byte, bool) {
	s.tokenMu.RLock()
	token := append([]byte(nil), s.token...)
	requireToken := s.requireToken
	s.tokenMu.RUnlock()
	return token, requireToken
}

func (s *Server) handleTransportRequest(transportRequest unixtransport.Request) json.RawMessage {
	var request Request
	if err := json.Unmarshal(transportRequest.Message, &request); err != nil || request.Method == "" {
		return s.encodeResponse(Response{Error: responseError(ErrInvalidRequest)})
	}
	token, requireToken := s.tokenSnapshot()
	if requireToken && (len(token) == 0 || subtle.ConstantTimeCompare([]byte(request.Token), token) != 1) {
		return s.encodeResponse(Response{Error: responseError(ErrUnauthorized)})
	}

	ctx, cancel := context.WithTimeout(transportRequest.Context, 30*time.Second)
	defer cancel()
	result, err := s.handler.Handle(ctx, request.Method, request.Params)
	if err != nil {
		return s.encodeResponse(Response{Error: responseError(err)})
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return s.encodeResponse(Response{Error: responseError(ErrInvalidRequest)})
	}
	return s.encodeResponse(Response{Result: encoded})
}

func (s *Server) encodeTransportFailure(failure unixtransport.Failure) json.RawMessage {
	if failure == unixtransport.FailureUnauthorizedPeer {
		return s.encodeResponse(Response{Error: responseError(ErrUnauthorized)})
	}
	return s.encodeResponse(Response{Error: responseError(ErrInvalidRequest)})
}

func (s *Server) encodeResponse(response Response) json.RawMessage {
	encoded, err := json.Marshal(response)
	if err != nil {
		return json.RawMessage(`{"error":{"code":"invalid_request","message":"invalid local control request"}}`)
	}
	return encoded
}

type Client struct {
	socketPath string
	token      string
}

func NewClient(socketPath, token string) *Client {
	return &Client{socketPath: socketPath, token: token}
}

func (c *Client) Call(ctx context.Context, method string, params any, result any) error {
	if method == "" {
		return ErrInvalidRequest
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode IPC parameters: %w", err)
	}
	connection, err := unixtransport.Dial(ctx, c.socketPath)
	if err != nil {
		return fmt.Errorf("connect to local IPC server: %w", err)
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
			return fmt.Errorf("set local IPC deadline: %w", err)
		}
	}
	if err := unixtransport.Encode(connection, Request{Token: c.token, Method: method, Params: encoded}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("write local IPC request: %w", err)
	}

	var response Response
	if err := unixtransport.Decode(connection, &response); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("read local IPC response: %w", err)
	}
	if response.Error != nil {
		return errorFromResponse(response.Error)
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode local IPC result: %w", err)
	}
	return nil
}

func responseError(err error) *ResponseError {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return &ResponseError{Code: "unauthorized", Message: "local control request was rejected"}
	case errors.Is(err, ErrMethodNotFound):
		return &ResponseError{Code: "method_not_found", Message: "local control method was not found"}
	case errors.Is(err, ErrInvalidRequest):
		return &ResponseError{Code: "invalid_request", Message: "invalid local control request"}
	case errors.Is(err, ErrLocked):
		return &ResponseError{Code: "locked", Message: "local credential store is locked"}
	case errors.Is(err, ErrCandidateNotDispatched):
		return &ResponseError{Code: "candidate_not_dispatched", Message: "candidate validation was not dispatched"}
	case errors.Is(err, ErrCandidateAuditWriteFailed):
		return &ResponseError{Code: "candidate_audit_write_failed", Message: "candidate validation audit write failed"}
	case errors.Is(err, ErrConfirmationRequired):
		return &ResponseError{Code: "confirmation_required", Message: "local confirmation is required"}
	case errors.Is(err, ErrCandidateConnectionFailed):
		return &ResponseError{Code: "candidate_connection_failed", Message: "candidate connection validation failed"}
	case errors.Is(err, ErrCandidateAuthenticationFailed):
		return &ResponseError{Code: "candidate_authentication_failed", Message: "candidate authentication validation failed"}
	case errors.Is(err, ErrCandidateTLSFailed):
		return &ResponseError{Code: "candidate_tls_failed", Message: "candidate TLS validation failed"}
	default:
		return &ResponseError{Code: "operation_failed", Message: "local control operation failed"}
	}
}

func errorFromResponse(response *ResponseError) error {
	switch response.Code {
	case "unauthorized":
		return ErrUnauthorized
	case "method_not_found":
		return ErrMethodNotFound
	case "invalid_request":
		return ErrInvalidRequest
	case "locked":
		return ErrLocked
	case "candidate_not_dispatched":
		return ErrCandidateNotDispatched
	case "candidate_audit_write_failed":
		return ErrCandidateAuditWriteFailed
	case "confirmation_required":
		return ErrConfirmationRequired
	case "candidate_connection_failed":
		return ErrCandidateConnectionFailed
	case "candidate_authentication_failed":
		return ErrCandidateAuthenticationFailed
	case "candidate_tls_failed":
		return ErrCandidateTLSFailed
	default:
		return errors.New(response.Message)
	}
}
