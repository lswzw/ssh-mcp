// Package worksession keeps the declared, non-interactive SSH context for a
// short-lived sequence of controlled operations. It never retains a shell,
// credential, remote output, or unobservable remote process state.
package worksession

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ssh-mcp/internal/redact"
)

const (
	DefaultIdleTimeout      = 5 * time.Minute
	expiredSessionRetention = time.Minute
)

var (
	ErrInvalidSession       = errors.New("invalid SSH work session")
	ErrSessionNotFound      = errors.New("SSH work session not found")
	ErrSessionExpired       = errors.New("SSH work session expired")
	ErrSessionInvalidated   = errors.New("SSH work session invalidated")
	ErrSessionOwnerMismatch = errors.New("SSH work session owner does not match")
	ErrInvalidContext       = errors.New("invalid SSH work session context")

	environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Context is the complete observable state preserved between SSH work-session
// commands. The directory and environment are always supplied structurally.
type Context struct {
	WorkingDirectory string            `json:"working_directory"`
	Environment      map[string]string `json:"environment"`
}

// Clone 返回上下文的独立副本，避免调用方通过环境变量映射修改已冻结的状态。
func (context Context) Clone() Context {
	if context.WorkingDirectory == "" && len(context.Environment) == 0 {
		return Context{}
	}
	result := Context{WorkingDirectory: context.WorkingDirectory, Environment: make(map[string]string, len(context.Environment))}
	for name, value := range context.Environment {
		result.Environment[name] = value
	}
	return result
}

// Session binds one declared context to one version of one registered target.
type Session struct {
	ID             string    `json:"id"`
	OwnerID        string    `json:"owner_id,omitempty"`
	Target         string    `json:"target"`
	TargetRevision int64     `json:"target_revision"`
	PolicyVersion  string    `json:"policy_version"`
	Context        Context   `json:"context"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Options struct {
	IdleTimeout   time.Duration
	Now           func() time.Time
	OnInvalidated func(Session)
}

type record struct {
	leaseGate    chan struct{}
	session      Session
	invalidated  bool
	dispatching  bool
	dispatchDone chan struct{}
	timer        *time.Timer
}

// Store serializes operations per session while allowing unrelated sessions to
// progress independently. Its contents are intentionally daemon-memory only.
type Store struct {
	mu            sync.Mutex
	idleTimeout   time.Duration
	now           func() time.Time
	onInvalidated func(Session)
	sessions      map[string]*record
	expired       map[string]time.Time
}

func New(options Options) *Store {
	idleTimeout := options.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Store{idleTimeout: idleTimeout, now: now, onInvalidated: options.OnInvalidated, sessions: make(map[string]*record), expired: make(map[string]time.Time)}
}

func (s *Store) Open(target string, revision int64, policyVersion string) (Session, error) {
	return s.open("", target, revision, policyVersion)
}

// OpenForOwner 创建只属于指定 bridge 执行主体的会话。
func (s *Store) OpenForOwner(ownerID, target string, revision int64, policyVersion string) (Session, error) {
	ownerID, err := requiredOwnerID(ownerID)
	if err != nil {
		return Session{}, err
	}
	return s.open(ownerID, target, revision, policyVersion)
}

func (s *Store) open(ownerID, target string, revision int64, policyVersion string) (Session, error) {
	if s == nil || strings.TrimSpace(target) == "" || strings.TrimSpace(policyVersion) == "" {
		return Session{}, ErrInvalidSession
	}
	id, err := sessionID()
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	session := Session{
		ID:             id,
		OwnerID:        ownerID,
		Target:         target,
		TargetRevision: revision,
		PolicyVersion:  policyVersion,
		Context:        Context{WorkingDirectory: "/", Environment: map[string]string{}},
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(s.idleTimeout),
	}
	s.mu.Lock()
	delete(s.expired, id)
	record := &record{session: session, leaseGate: make(chan struct{}, 1)}
	record.leaseGate <- struct{}{}
	s.sessions[id] = record
	s.armExpiryLocked(record)
	s.mu.Unlock()
	return cloneSession(session), nil
}

// Acquire 串行化单个会话操作。调用方必须释放 lease，并且只能在操作通过准入后调用 Accept。
func (s *Store) Acquire(id string) (*Lease, error) {
	return s.acquireContext(context.Background(), "", id)
}

// AcquireForOwner 只向会话创建主体授予会话操作租约。
func (s *Store) AcquireForOwner(ownerID, id string) (*Lease, error) {
	return s.AcquireContextForOwner(context.Background(), ownerID, id)
}

// AcquireContext 在等待同一会话的既有操作时遵守调用方的截止时间。
func (s *Store) AcquireContext(ctx context.Context, id string) (*Lease, error) {
	return s.acquireContext(ctx, "", id)
}

// AcquireContextForOwner 在等待租约时校验执行主体并遵守调用方截止时间。
func (s *Store) AcquireContextForOwner(ctx context.Context, ownerID, id string) (*Lease, error) {
	ownerID, err := requiredOwnerID(ownerID)
	if err != nil {
		return nil, err
	}
	return s.acquireContext(ctx, ownerID, id)
}

func (s *Store) acquireContext(ctx context.Context, ownerID, id string) (*Lease, error) {
	if s == nil || strings.TrimSpace(id) == "" {
		return nil, ErrInvalidSession
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	record, ok := s.sessions[id]
	if !ok {
		_, expired := s.expired[id]
		s.mu.Unlock()
		if expired {
			return nil, ErrSessionExpired
		}
		return nil, ErrSessionNotFound
	}
	if !sessionOwnedBy(record.session, ownerID) {
		s.mu.Unlock()
		return nil, ErrSessionOwnerMismatch
	}
	if !s.now().Before(record.session.ExpiresAt) {
		session, dispatchDone, invalidated := s.invalidateLocked(id, record)
		if invalidated {
			s.rememberExpiredLocked(id)
		}
		s.mu.Unlock()
		if err := s.waitForInvalidatedSession(ctx, session, dispatchDone, invalidated); err != nil {
			return nil, err
		}
		return nil, ErrSessionExpired
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-record.leaseGate:
	}
	releaseGate := true
	defer func() {
		if releaseGate {
			record.leaseGate <- struct{}{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.sessions[id] != record || record.invalidated {
		_, expired := s.expired[id]
		s.mu.Unlock()
		if expired {
			return nil, ErrSessionExpired
		}
		return nil, ErrSessionInvalidated
	}
	if !sessionOwnedBy(record.session, ownerID) {
		s.mu.Unlock()
		return nil, ErrSessionOwnerMismatch
	}
	if !s.now().Before(record.session.ExpiresAt) {
		session, dispatchDone, invalidated := s.invalidateLocked(id, record)
		if invalidated {
			s.rememberExpiredLocked(id)
		}
		s.mu.Unlock()
		if err := s.waitForInvalidatedSession(ctx, session, dispatchDone, invalidated); err != nil {
			return nil, err
		}
		return nil, ErrSessionExpired
	}
	s.mu.Unlock()
	releaseGate = false
	return &Lease{store: s, record: record}, nil
}

// Close removes one session. It is safe to call repeatedly, including after
// expiration, because no remote command is sent as part of closing.
func (s *Store) Close(id string) (Session, bool) {
	session, err := s.closeForOwner("", id)
	return session, err == nil
}

// CloseForOwner 仅允许会话创建主体关闭其会话。
func (s *Store) CloseForOwner(ownerID, id string) (Session, error) {
	ownerID, err := requiredOwnerID(ownerID)
	if err != nil {
		return Session{}, err
	}
	return s.closeForOwner(ownerID, id)
}

func (s *Store) closeForOwner(ownerID, id string) (Session, error) {
	if s == nil || strings.TrimSpace(id) == "" {
		return Session{}, ErrInvalidSession
	}
	s.mu.Lock()
	record, ok := s.sessions[id]
	if !ok {
		delete(s.expired, id)
		s.mu.Unlock()
		return Session{}, ErrSessionNotFound
	}
	if !sessionOwnedBy(record.session, ownerID) {
		s.mu.Unlock()
		return Session{}, ErrSessionOwnerMismatch
	}
	session, dispatchDone, invalidated := s.invalidateLocked(id, record)
	s.mu.Unlock()
	waitForDispatch(dispatchDone)
	if invalidated {
		s.notifyInvalidated(session)
	}
	if !invalidated {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

// ClearTarget invalidates every session bound to the exact target. Running
// operations cannot be rolled back, but no later command can be dispatched.
func (s *Store) ClearTarget(target string) {
	if s == nil || strings.TrimSpace(target) == "" {
		return
	}
	s.mu.Lock()
	dispatches := make([]<-chan struct{}, 0)
	invalidated := make([]Session, 0)
	for id, record := range s.sessions {
		if record.session.Target == target {
			session, dispatchDone, didInvalidate := s.invalidateLocked(id, record)
			if didInvalidate {
				dispatches = append(dispatches, dispatchDone)
				invalidated = append(invalidated, session)
			}
		}
	}
	s.mu.Unlock()
	waitForDispatches(dispatches)
	for _, session := range invalidated {
		s.notifyInvalidated(session)
	}
}

// ClearOwner 使指定执行主体的全部易失会话失效。已经领取派发的会话会先收束。
func (s *Store) ClearOwner(ownerID string) {
	if s == nil {
		return
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return
	}
	s.mu.Lock()
	dispatches := make([]<-chan struct{}, 0)
	invalidated := make([]Session, 0)
	for id, record := range s.sessions {
		if !sessionOwnedBy(record.session, ownerID) {
			continue
		}
		session, dispatchDone, didInvalidate := s.invalidateLocked(id, record)
		if didInvalidate {
			dispatches = append(dispatches, dispatchDone)
			invalidated = append(invalidated, session)
		}
	}
	s.mu.Unlock()
	waitForDispatches(dispatches)
	for _, session := range invalidated {
		s.notifyInvalidated(session)
	}
}

func (s *Store) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	dispatches := make([]<-chan struct{}, 0, len(s.sessions))
	invalidated := make([]Session, 0, len(s.sessions))
	for id, record := range s.sessions {
		session, dispatchDone, didInvalidate := s.invalidateLocked(id, record)
		if didInvalidate {
			dispatches = append(dispatches, dispatchDone)
			invalidated = append(invalidated, session)
		}
	}
	s.expired = make(map[string]time.Time)
	s.mu.Unlock()
	waitForDispatches(dispatches)
	for _, session := range invalidated {
		s.notifyInvalidated(session)
	}
}

// Lease is an exclusive, short-lived handle for one accepted session action.
type Lease struct {
	store    *Store
	record   *record
	released bool
}

func (l *Lease) Session() Session {
	if l == nil || l.record == nil {
		return Session{}
	}
	return cloneSession(l.record.session)
}

func (l *Lease) SetContext(context Context) (Session, error) {
	if l == nil || l.released || l.record == nil {
		return Session{}, ErrInvalidSession
	}
	if err := ValidateContext(context); err != nil {
		return Session{}, err
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.store.sessions[l.record.session.ID] != l.record || l.record.invalidated {
		return Session{}, ErrSessionInvalidated
	}
	l.record.session.Context = context.Clone()
	return l.acceptLocked(), nil
}

// Accept refreshes the idle deadline after an accepted execution or structured
// context modification. It deliberately has no standalone heartbeat API.
func (l *Lease) Accept() Session {
	if l == nil || l.released || l.record == nil || l.store == nil {
		return Session{}
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.store.sessions[l.record.session.ID] != l.record || l.record.invalidated {
		return Session{}
	}
	return l.acceptLocked()
}

// BeginDispatch atomically reserves the right to send one accepted command.
// Invalidation that wins first prevents dispatch; invalidation that follows
// waits for FinishDispatch so it cannot cut between this check and transport.
func (l *Lease) BeginDispatch() bool {
	if l == nil || l.released || l.record == nil || l.store == nil {
		return false
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.store.sessions[l.record.session.ID] != l.record || l.record.invalidated || l.record.dispatching {
		return false
	}
	l.record.dispatching = true
	l.record.dispatchDone = make(chan struct{})
	return true
}

// FinishDispatch releases the reservation made by BeginDispatch. It is safe
// to call more than once so callers can defer it beside Release.
func (l *Lease) FinishDispatch() {
	if l == nil || l.record == nil || l.store == nil {
		return
	}
	l.store.mu.Lock()
	if !l.record.dispatching {
		l.store.mu.Unlock()
		return
	}
	dispatchDone := l.record.dispatchDone
	l.record.dispatching = false
	l.record.dispatchDone = nil
	l.store.mu.Unlock()
	if dispatchDone != nil {
		close(dispatchDone)
	}
}

func (l *Lease) acceptLocked() Session {
	now := l.store.now()
	l.record.session.LastActivityAt = now
	l.record.session.ExpiresAt = now.Add(l.store.idleTimeout)
	l.store.armExpiryLocked(l.record)
	return cloneSession(l.record.session)
}

func (l *Lease) Release() {
	if l == nil || l.released || l.record == nil {
		return
	}
	l.FinishDispatch()
	l.released = true
	l.record.leaseGate <- struct{}{}
}

// ValidateContext accepts only an absolute directory and observable,
// non-secret environment values. Replacing the whole map is the only context
// modification path; raw cd, export, unset, and source cannot persist state.
func ValidateContext(context Context) error {
	directory := context.WorkingDirectory
	if directory == "" || len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") || !path.IsAbs(directory) || path.Clean(directory) != directory {
		return ErrInvalidContext
	}
	if len(context.Environment) > 32 {
		return ErrInvalidContext
	}
	for name, value := range context.Environment {
		if !environmentName.MatchString(name) || sensitiveEnvironmentName(name) || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") || redact.Text(value).Redacted {
			return ErrInvalidContext
		}
	}
	return nil
}

// WrapCommand constructs the daemon-owned, non-interactive shell boundary for
// a session command. Inputs have already been validated and are always quoted.
func (context Context) WrapCommand(command string) string {
	names := make([]string, 0, len(context.Environment))
	for name := range context.Environment {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := []string{"cd " + shellQuote(context.WorkingDirectory), "&&", "env"}
	for _, name := range names {
		parts = append(parts, shellQuote(name+"="+context.Environment[name]))
	}
	parts = append(parts, "/bin/sh", "-c", shellQuote(command))
	return strings.Join(parts, " ")
}

func sensitiveEnvironmentName(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "accesskey", "credential", "privatekey", "authorization", "cookie"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	switch strings.ToUpper(name) {
	case "PATH", "HOME", "SHELL", "IFS", "ENV", "BASH_ENV", "PROMPT_COMMAND", "CDPATH", "GIT_ASKPASS", "SSH_ASKPASS":
		return true
	default:
		return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func sessionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate SSH work session ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func requiredOwnerID(ownerID string) (string, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return "", ErrInvalidSession
	}
	return ownerID, nil
}

func sessionOwnedBy(session Session, ownerID string) bool {
	return session.OwnerID == ownerID
}

func cloneSession(session Session) Session {
	session.Context = session.Context.Clone()
	return session
}

func (s *Store) armExpiryLocked(record *record) {
	stopExpiry(record)
	id, expiresAt := record.session.ID, record.session.ExpiresAt
	record.timer = time.AfterFunc(s.idleTimeout, func() {
		s.expire(id, expiresAt)
	})
}

func (s *Store) expire(id string, expiresAt time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	record, ok := s.sessions[id]
	if !ok || record.invalidated || !record.session.ExpiresAt.Equal(expiresAt) {
		s.mu.Unlock()
		return
	}
	session, dispatchDone, invalidated := s.invalidateLocked(id, record)
	if invalidated {
		s.rememberExpiredLocked(id)
	}
	s.mu.Unlock()
	waitForDispatch(dispatchDone)
	if invalidated {
		s.notifyInvalidated(session)
	}
}

func (s *Store) invalidateLocked(id string, record *record) (Session, <-chan struct{}, bool) {
	if s.sessions[id] != record || record.invalidated {
		return Session{}, nil, false
	}
	session := cloneSession(record.session)
	record.invalidated = true
	stopExpiry(record)
	delete(s.sessions, id)
	return session, record.dispatchDone, true
}

func (s *Store) rememberExpiredLocked(id string) {
	if s == nil || id == "" {
		return
	}
	expiresAt := time.Now().Add(expiredSessionRetention)
	s.expired[id] = expiresAt
	time.AfterFunc(expiredSessionRetention, func() {
		s.mu.Lock()
		if recorded, ok := s.expired[id]; ok && recorded.Equal(expiresAt) {
			delete(s.expired, id)
		}
		s.mu.Unlock()
	})
}

func waitForDispatch(dispatchDone <-chan struct{}) {
	if dispatchDone != nil {
		<-dispatchDone
	}
}

func (s *Store) waitForInvalidatedSession(ctx context.Context, session Session, dispatchDone <-chan struct{}, invalidated bool) error {
	if !invalidated {
		return nil
	}
	if dispatchDone == nil {
		s.notifyInvalidated(session)
		return nil
	}
	select {
	case <-dispatchDone:
		s.notifyInvalidated(session)
		return nil
	case <-ctx.Done():
		go func() {
			waitForDispatch(dispatchDone)
			s.notifyInvalidated(session)
		}()
		return ctx.Err()
	}
}

func waitForDispatches(dispatches []<-chan struct{}) {
	for _, dispatchDone := range dispatches {
		waitForDispatch(dispatchDone)
	}
}

func (s *Store) notifyInvalidated(session Session) {
	if s == nil || s.onInvalidated == nil || session.ID == "" {
		return
	}
	s.onInvalidated(cloneSession(session))
}

func stopExpiry(record *record) {
	if record == nil || record.timer == nil {
		return
	}
	record.timer.Stop()
	record.timer = nil
}
