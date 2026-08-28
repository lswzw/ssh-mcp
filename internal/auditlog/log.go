// Package auditlog persists local, human-readable audit events without
// placing operation contents in the credential SQLite database.
package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/paths"
	"ssh-mcp/internal/redact"
)

const (
	FileName         = "audit.log"
	DefaultMaxBytes  = 20 << 20
	DefaultArchives  = 10
	writeQueueSize   = 32
	closeWaitTimeout = time.Second

	PhaseStarted   = "started"
	PhaseCompleted = "completed"
	PhaseFailed    = "failed"
	PhaseDecision  = "decision"
)

var (
	errLoggerClosed       = errors.New("审计日志已关闭")
	errLoggerCloseTimeout = errors.New("关闭审计写入器超时")
)

type Actor struct {
	User             string `json:"user,omitempty"`
	PID              int    `json:"pid,omitempty"`
	WorkingDirectory string `json:"cwd,omitempty"`
	Source           string `json:"source,omitempty"`
	BridgeSessionID  string `json:"bridge_session_id,omitempty"`
}

type Target struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
}

type Policy struct {
	Version  string `json:"version,omitempty"`
	Decision string `json:"decision,omitempty"`
	Risk     string `json:"risk,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type Result struct {
	Status            string `json:"status,omitempty"`
	Summary           string `json:"summary,omitempty"`
	ExitStatus        *int   `json:"exit_status,omitempty"`
	AffectedRows      *int64 `json:"affected_rows,omitempty"`
	DurationMS        *int64 `json:"duration_ms,omitempty"`
	OutputTruncated   bool   `json:"output_truncated,omitempty"`
	RowsTruncated     bool   `json:"rows_truncated,omitempty"`
	TransportSecurity string `json:"transport_security,omitempty"`
	AuditWriteFailed  bool   `json:"audit_write_failed,omitempty"`
}

// FileRead records file-inspection metadata only. Remote file content never
// belongs in the local audit trail.
type FileRead struct {
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	BytesRead *int   `json:"bytes_read,omitempty"`
}

// Deployment records the irreversible remote-file transition as metadata.
// It intentionally has no local source path, source bytes, remote error
// text, or service-manager output.
type Deployment struct {
	RemotePath    string `json:"remote_path"`
	BackupPath    string `json:"backup_path,omitempty"`
	BytesUploaded int64  `json:"bytes_uploaded,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Activated     bool   `json:"activated"`
	StartStatus   string `json:"start_status,omitempty"`
}

type Event struct {
	Time           time.Time   `json:"time"`
	OperationID    string      `json:"operation_id,omitempty"`
	Phase          string      `json:"phase"`
	RemoteExecuted bool        `json:"remote_executed"`
	Action         string      `json:"action,omitempty"`
	Actor          Actor       `json:"actor,omitempty"`
	Target         Target      `json:"target"`
	Policy         Policy      `json:"policy,omitempty"`
	SSHCommand     string      `json:"ssh_command,omitempty"`
	SQL            string      `json:"sql,omitempty"`
	File           *FileRead   `json:"file,omitempty"`
	Deployment     *Deployment `json:"deployment,omitempty"`
	Result         Result      `json:"result,omitempty"`
}

// Recorder is the runner's append-only audit boundary.
type Recorder interface {
	Record(context.Context, Event) error
}

type Options struct {
	MaxBytes int64
	Archives int
	Now      func() time.Time
}

type writeRequest struct {
	ctx     context.Context
	encoded []byte
	done    chan error
}

type Logger struct {
	path          string
	maxBytes      int64
	archives      int
	now           func() time.Time
	writeQueue    chan writeRequest
	appendEncoded func(context.Context, []byte) error
	enqueueGate   chan struct{}
	closing       chan struct{}
	stop          chan struct{}
	stopped       chan struct{}
	closeOnce     sync.Once
}

func New(path string) *Logger {
	return NewWithOptions(path, Options{})
}

func NewWithOptions(path string, options Options) *Logger {
	maxBytes := options.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	archives := options.Archives
	if archives <= 0 {
		archives = DefaultArchives
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := &Logger{
		path:        path,
		maxBytes:    maxBytes,
		archives:    archives,
		now:         now,
		writeQueue:  make(chan writeRequest, writeQueueSize),
		enqueueGate: make(chan struct{}, 1),
		closing:     make(chan struct{}),
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	logger.enqueueGate <- struct{}{}
	logger.appendEncoded = logger.append
	go logger.writeEvents()
	return logger
}

func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close 拒绝后续审计请求，并最多等待一秒让当前磁盘写入结束。
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		close(l.closing)
		<-l.enqueueGate
		close(l.stop)
		l.enqueueGate <- struct{}{}
	})
	select {
	case <-l.stopped:
		return nil
	case <-time.After(closeWaitTimeout):
		return errLoggerCloseTimeout
	}
}

func (l *Logger) Record(ctx context.Context, event Event) error {
	if l == nil || strings.TrimSpace(l.path) == "" {
		return errors.New("audit log is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = clock.InBeijing(l.now())
	}
	event = sanitizeEvent(event)
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	encoded = append(encoded, '\n')

	request := writeRequest{ctx: ctx, encoded: encoded, done: make(chan error, 1)}
	select {
	case <-l.closing:
		return errLoggerClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-l.enqueueGate:
	}
	defer func() { l.enqueueGate <- struct{}{} }()
	select {
	case <-l.closing:
		return errLoggerClosed
	default:
	}
	select {
	case <-l.closing:
		return errLoggerClosed
	case <-ctx.Done():
		return ctx.Err()
	case l.writeQueue <- request:
	}
	select {
	case <-l.closing:
		return errLoggerClosed
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.done:
		return err
	}
}

func (l *Logger) writeEvents() {
	defer close(l.stopped)
	for {
		select {
		case <-l.stop:
			l.rejectQueuedWrites()
			return
		case request := <-l.writeQueue:
			select {
			case <-l.closing:
				request.done <- errLoggerClosed
				continue
			default:
			}
			l.writeRequest(request)
		}
	}
}

func (l *Logger) writeRequest(request writeRequest) {
	if err := request.ctx.Err(); err != nil {
		request.done <- err
		return
	}
	request.done <- l.appendEncoded(request.ctx, request.encoded)
}

func (l *Logger) rejectQueuedWrites() {
	for {
		select {
		case request := <-l.writeQueue:
			request.done <- errLoggerClosed
		default:
			return
		}
	}
}

func (l *Logger) append(ctx context.Context, encoded []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.rotateIfNeeded(int64(len(encoded))); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := openAuditAppend(l.path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync audit event: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (l *Logger) rotateIfNeeded(nextSize int64) error {
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log must be a regular file")
	}
	if info.Size()+nextSize <= l.maxBytes {
		return nil
	}
	for index := l.archives; index >= 1; index-- {
		source := archivePath(l.path, index)
		if index == l.archives {
			if err := removeRegularAuditFileIfPresent(source); err != nil {
				return err
			}
			continue
		}
		destination := archivePath(l.path, index+1)
		if err := renameRegularAuditFileIfPresent(source, destination); err != nil {
			return err
		}
	}
	if err := ensureRegularAuditFile(l.path); err != nil {
		return err
	}
	if err := paths.ReplaceFile(l.path, archivePath(l.path, 1)); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}
	return paths.SyncDirectory(filepath.Dir(l.path))
}

func archivePath(path string, index int) string {
	return fmt.Sprintf("%s.%d", path, index)
}

func renameRegularAuditFileIfPresent(source, destination string) error {
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit archive: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit archive must be a regular file")
	}
	if err := ensureRegularAuditFileIfPresent(destination); err != nil {
		return err
	}
	if err := paths.ReplaceFile(source, destination); err != nil {
		return fmt.Errorf("rotate audit archive: %w", err)
	}
	return nil
}

func removeRegularAuditFileIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit archive destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit archive must be a regular file")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove expired audit archive: %w", err)
	}
	return nil
}

func openAuditAppend(path string) (*os.File, error) {
	if err := ensureParentDirectory(path); err != nil {
		return nil, err
	}
	if err := ensureRegularAuditFileIfPresent(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o666)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect audit log: %w", err)
		}
		return nil, errors.New("audit log must be a regular file")
	}
	return file, nil
}

func ensureParentDirectory(path string) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect audit directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("audit directory must be a directory")
	}
	if err := paths.EnsureDirectory(directory); err != nil {
		return fmt.Errorf("prepare audit directory: %w", err)
	}
	return nil
}

func ensureRegularAuditFileIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log must be a regular file")
	}
	return nil
}

func ensureRegularAuditFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log must be a regular file")
	}
	return nil
}

func sanitizeEvent(event Event) Event {
	if event.SSHCommand != "" {
		event.SSHCommand = redact.Text(event.SSHCommand).Value
	}
	if event.SQL != "" {
		event.SQL = redactSQLLiterals(event.SQL)
	}
	return event
}

var (
	sqlLineComment  = regexp.MustCompile(`(?m)--[^\r\n]*`)
	sqlHashComment  = regexp.MustCompile(`(?m)#[^\r\n]*`)
	sqlBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

func redactSQLLiterals(value string) string {
	value = sqlLineComment.ReplaceAllString(value, redact.Marker)
	value = sqlHashComment.ReplaceAllString(value, redact.Marker)
	value = sqlBlockComment.ReplaceAllString(value, redact.Marker)
	var result strings.Builder
	for index := 0; index < len(value); {
		current := value[index]
		if current == '\'' {
			index = consumeSingleQuoted(value, index)
			result.WriteString(redact.Marker)
			continue
		}
		if current == '"' {
			index = consumeDoubleQuoted(value, index)
			result.WriteString(redact.Marker)
			continue
		}
		if current == '$' {
			if end, ok := consumeDollarQuoted(value, index); ok {
				index = end
				result.WriteString(redact.Marker)
				continue
			}
		}
		if numericLiteralStart(value, index) {
			index = consumeNumericLiteral(value, index)
			result.WriteString(redact.Marker)
			continue
		}
		result.WriteByte(current)
		index++
	}
	return result.String()
}

func consumeDoubleQuoted(value string, start int) int {
	index := start + 1
	for index < len(value) {
		if value[index] != '"' {
			index++
			continue
		}
		if index+1 < len(value) && value[index+1] == '"' {
			index += 2
			continue
		}
		return index + 1
	}
	return len(value)
}

func consumeSingleQuoted(value string, start int) int {
	index := start + 1
	for index < len(value) {
		if value[index] != '\'' {
			index++
			continue
		}
		if index+1 < len(value) && value[index+1] == '\'' {
			index += 2
			continue
		}
		return index + 1
	}
	return len(value)
}

func consumeDollarQuoted(value string, start int) (int, bool) {
	endTag := start + 1
	for endTag < len(value) && (value[endTag] == '_' || value[endTag] >= 'a' && value[endTag] <= 'z' || value[endTag] >= 'A' && value[endTag] <= 'Z' || value[endTag] >= '0' && value[endTag] <= '9') {
		endTag++
	}
	if endTag >= len(value) || value[endTag] != '$' {
		return start, false
	}
	tag := value[start : endTag+1]
	closing := strings.Index(value[endTag+1:], tag)
	if closing < 0 {
		return len(value), true
	}
	return endTag + 1 + closing + len(tag), true
}

func numericLiteralStart(value string, index int) bool {
	if value[index] < '0' || value[index] > '9' {
		return false
	}
	if index == 0 {
		return true
	}
	previous := value[index-1]
	return !(previous == '_' || previous >= 'a' && previous <= 'z' || previous >= 'A' && previous <= 'Z' || previous >= '0' && previous <= '9')
}

func consumeNumericLiteral(value string, start int) int {
	index := start
	if index+2 <= len(value) && value[index] == '0' && index+1 < len(value) && (value[index+1] == 'x' || value[index+1] == 'X') {
		index += 2
		for index < len(value) && (value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f' || value[index] >= 'A' && value[index] <= 'F') {
			index++
		}
		return index
	}
	for index < len(value) && (value[index] >= '0' && value[index] <= '9' || value[index] == '.' || value[index] == 'e' || value[index] == 'E' || value[index] == '+' || value[index] == '-') {
		index++
	}
	return index
}
