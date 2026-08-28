// Package runner is the only path from MCP tool input to remote transport.
// It resolves registered targets, enforces session and read-only policy
// boundaries, and records a local audit entry for every security decision.
package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/dbservice"
	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
	"ssh-mcp/internal/worksession"
)

const (
	StatusCompleted                = "completed"
	StatusNotDispatched            = "not_dispatched"
	StatusOutcomeUnknown           = "outcome_unknown"
	StatusUnlockRequired           = "unlock_required"
	StatusTargetNotFound           = "target_not_found"
	StatusDatabaseNotFound         = "database_not_found"
	StatusRejected                 = "rejected"
	StatusFailed                   = "failed"
	StatusAuditWriteFailed         = "audit_write_failed"
	StatusInteractiveInputRequired = "interactive_input_required"
	StatusSSHSessionOpened         = "ssh_session_opened"
	StatusSSHSessionContextUpdated = "ssh_session_context_updated"
	StatusSSHSessionClosed         = "ssh_session_closed"
	StatusSSHSessionNotFound       = "ssh_session_not_found"
	StatusSSHSessionExpired        = "ssh_session_expired"
	StatusSSHSessionInvalidated    = "ssh_session_invalidated"
	ExecutionOutcomeFailedKnown    = "failed_known"
	AuditOutcomeRecorded           = "recorded"
	AuditOutcomeFailed             = "failed"
	FailureKindWriteCredential     = "write_credential_not_configured"
	// 每次操作的终态审计调用最多等待一秒。
	terminalAuditTimeout = time.Second
)

type TargetStore interface {
	ListSSHTargets(context.Context) ([]store.SSHTarget, error)
	ListDatabaseInstances(context.Context) ([]store.DatabaseInstance, error)
	SSHTarget(context.Context, string) (store.SSHTarget, error)
	DatabaseInstance(context.Context, string, int) (store.DatabaseInstance, error)
}

type Session interface {
	Vault() (*store.Vault, error)
	TouchRemoteActivity()
}

type SSHService interface {
	Execute(context.Context, *store.Vault, store.SSHTarget, string, bool, int) (sshtransport.ExecutionResult, error)
	ExecuteIsolated(context.Context, *store.Vault, store.SSHTarget, string, string, bool, int) (sshtransport.ExecutionResult, error)
}

// SSHFileReader is the narrow runner boundary for constrained read-only file
// inspection. It deliberately does not expose a generic SFTP client.
type SSHFileReader interface {
	ReadFile(context.Context, *store.Vault, store.SSHTarget, string, int64, int) (sshtransport.FileReadResult, error)
}

// SSHBinaryDeployer is the single runner write boundary. The runner validates
// the direct request; the transport owns its temporary and backup paths.
type SSHBinaryDeployer interface {
	DeployBinary(context.Context, *store.Vault, store.SSHTarget, io.Reader, sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error)
}

type sshExecutionScope uint8

const (
	sshExecutionDedicated sshExecutionScope = iota
	sshExecutionIsolated
)

type DatabaseService interface {
	ListDatabases(context.Context, *store.Vault, store.DatabaseInstance) (dbtransport.DatabaseListResult, error)
	Query(context.Context, *store.Vault, store.DatabaseInstance, string, string, dbtransport.Limits) (dbtransport.QueryResult, error)
	ExecuteStatements(context.Context, *store.Vault, store.DatabaseInstance, string, []string) (dbtransport.ExecutionResult, error)
}

type Auditor interface {
	Record(context.Context, auditlog.Event) error
}

type Dependencies struct {
	Targets            TargetStore
	Sessions           Session
	SSH                SSHService
	FileReader         SSHFileReader
	Deployer           SSHBinaryDeployer
	Database           DatabaseService
	WorkSessions       *worksession.Store
	DatabaseAuthorizer *DatabaseTargetAuthorizer
	DispatchBarrier    *DispatchBarrier
	TargetLanes        *TargetLanes
	Audit              Auditor
	Limiter            *policy.Limiter
	OpenTUI            func() error
	Now                func() time.Time
	AuditActor         auditlog.Actor
	SessionID          string
	ExecutionOwner     string
}

type Engine struct {
	deps Dependencies
}

func New(deps Dependencies) *Engine {
	if deps.Limiter == nil {
		deps.Limiter = policy.NewLimiter(4)
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.WorkSessions == nil {
		deps.WorkSessions = worksession.New(worksession.Options{Now: deps.Now})
	}
	if deps.DispatchBarrier == nil {
		deps.DispatchBarrier = NewDispatchBarrier()
	}
	if deps.TargetLanes == nil {
		deps.TargetLanes = NewTargetLanes()
	}
	if deps.AuditActor.BridgeSessionID == "" {
		deps.AuditActor.BridgeSessionID = strings.TrimSpace(deps.SessionID)
	}
	if deps.AuditActor.BridgeSessionID == "" {
		deps.AuditActor.BridgeSessionID = "unknown"
	}
	return &Engine{deps: deps}
}

func (e *Engine) evaluateSSH(ctx context.Context, request policy.SSHRequest) policy.Result {
	request.RegisteredRemoteTargets, request.RemoteTargetRegistryAvailable = e.registeredRemoteTargets(ctx)
	return policy.EvaluateSSH(request)
}

func (e *Engine) evaluateSQL(request policy.SQLRequest) policy.Result {
	return policy.EvaluateSQL(request)
}

// registeredRemoteTargets supplies the policy with the local, non-secret
// identity snapshot used to authorize nested SSH-family destinations. A
// registry read failure deliberately leaves the snapshot unavailable, which
// makes only nested remote hops fail closed under their fixed hard-stop rule.
func (e *Engine) registeredRemoteTargets(ctx context.Context) ([]policy.RegisteredRemoteTarget, bool) {
	if e == nil || e.deps.Targets == nil {
		return nil, false
	}
	targets, err := e.deps.Targets.ListSSHTargets(ctx)
	if err != nil {
		return nil, false
	}
	registered := make([]policy.RegisteredRemoteTarget, 0, len(targets))
	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		registered = append(registered, policy.RegisteredRemoteTarget{Host: target.IP, Port: sshPort(target)})
	}
	return registered, true
}

// WithAuditSession retains compatibility for callers that only have a bridge ID.
func (e *Engine) WithAuditSession(sessionID string) *Engine {
	return e.WithAuditActor(auditlog.Actor{BridgeSessionID: sessionID})
}

// WithAuditActor returns a view over the same remote services and limiter.
func (e *Engine) WithAuditActor(actor auditlog.Actor) *Engine {
	if e == nil {
		return nil
	}
	clone := *e
	if strings.TrimSpace(actor.BridgeSessionID) == "" {
		actor.BridgeSessionID = clone.deps.AuditActor.BridgeSessionID
	}
	clone.deps.AuditActor = actor
	return &clone
}

// WithExecutionOwner 将易失状态绑定到一个 bridge 执行主体。
func (e *Engine) WithExecutionOwner(ownerID string) *Engine {
	if e == nil {
		return nil
	}
	clone := *e
	clone.deps.ExecutionOwner = strings.TrimSpace(ownerID)
	return &clone
}

// LockDispatch 先阻断新派发，再等待已经开始的远端操作收束。
func (e *Engine) LockDispatch(ctx context.Context) error {
	if e == nil || e.deps.DispatchBarrier == nil {
		return nil
	}
	return e.deps.DispatchBarrier.Lock(ctx)
}

func (e *Engine) UnlockDispatch() {
	if e == nil || e.deps.DispatchBarrier == nil {
		return
	}
	e.deps.DispatchBarrier.Unlock()
}

// BlockDispatch 立即拒绝新的远端派发，但不等待当前调用自身收束。
// 强制停机与本地安全状态失效使用该失败关闭边界。
func (e *Engine) BlockDispatch() {
	if e == nil || e.deps.DispatchBarrier == nil {
		return
	}
	e.deps.DispatchBarrier.Block()
}

func (e *Engine) acquireTargetLane(ctx context.Context, protocol TargetProtocol, target string) (func(), error) {
	if e == nil || e.deps.TargetLanes == nil {
		return nil, ErrInvalidTargetLane
	}
	return e.deps.TargetLanes.AcquireWrite(ctx, string(protocol)+":"+target)
}

func (e *Engine) acquireTargetReadLane(ctx context.Context, protocol TargetProtocol, target string) (func(), error) {
	if e == nil || e.deps.TargetLanes == nil {
		return nil, ErrInvalidTargetLane
	}
	return e.deps.TargetLanes.AcquireRead(ctx, string(protocol)+":"+target)
}

type SSHTarget struct {
	IP                  string `json:"ip"`
	Port                int    `json:"port"`
	Description         string `json:"description,omitempty"`
	Environment         string `json:"environment,omitempty"`
	Enabled             bool   `json:"enabled"`
	FileReadAvailable   bool   `json:"file_read_available"`
	AllowFileOperations bool   `json:"allow_file_operations"`
}

type DatabaseTarget struct {
	Target      string               `json:"target"`
	Engine      store.DatabaseEngine `json:"engine"`
	Description string               `json:"description,omitempty"`
	Environment string               `json:"environment,omitempty"`
	Enabled     bool                 `json:"enabled"`
}

type TargetsResult struct {
	SSH       []SSHTarget      `json:"ssh"`
	Databases []DatabaseTarget `json:"databases"`
}

type TargetProtocol string

const (
	ProtocolSSH TargetProtocol = "ssh"
	ProtocolSQL TargetProtocol = "sql"
)

// ExecutionSpecificationRequest asks only for a registered target's declared
// execution boundary. It never requires a vault or a remote connection.
type ExecutionSpecificationRequest struct {
	Target   string         `json:"target"`
	Protocol TargetProtocol `json:"protocol"`
}

// ExecutionSpecification is the non-sensitive portion of the execution specification
// visible to an MCP client before it submits an operation.
type ExecutionSpecification struct {
	Target          string         `json:"target"`
	Protocol        TargetProtocol `json:"protocol"`
	Available       bool           `json:"available"`
	PolicyVersion   string         `json:"policy_version"`
	DirectExecution []string       `json:"direct_execution"`
	// AbsoluteProhibitions is retained for protocol compatibility. It lists
	// only fixed hard-stop IDs recognized by this daemon version, rather than
	// a semantic or MCP-external universal prohibition.
	AbsoluteProhibitions                  []string `json:"absolute_prohibitions"`
	MaxOperationSeconds                   int      `json:"max_operation_seconds"`
	DefaultOutputBytes                    int      `json:"default_output_bytes"`
	MaxOutputBytes                        int      `json:"max_output_bytes"`
	MaxRows                               int      `json:"max_rows,omitempty"`
	FileReadAvailable                     bool     `json:"file_read_available,omitempty"`
	FileReadDefaultBytes                  int      `json:"file_read_default_bytes,omitempty"`
	FileReadMaxBytes                      int      `json:"file_read_max_bytes,omitempty"`
	FileReadDefaultTimeoutSeconds         int      `json:"file_read_default_timeout_seconds,omitempty"`
	FileReadMaxTimeoutSeconds             int      `json:"file_read_max_timeout_seconds,omitempty"`
	BinaryDeploymentAvailable             bool     `json:"binary_deployment_available,omitempty"`
	BinaryDeploymentDefaultBytes          int64    `json:"binary_deployment_default_bytes,omitempty"`
	BinaryDeploymentMaxBytes              int64    `json:"binary_deployment_max_bytes,omitempty"`
	BinaryDeploymentDefaultTimeoutSeconds int      `json:"binary_deployment_default_timeout_seconds,omitempty"`
	BinaryDeploymentMaxTimeoutSeconds     int      `json:"binary_deployment_max_timeout_seconds,omitempty"`
	AllowFileOperations                   bool     `json:"allow_file_operations"`
}

type SSHRequest struct {
	Target   string        `json:"target"`
	Command  string        `json:"command"`
	AsRoot   bool          `json:"as_root,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
	MaxBytes int           `json:"max_bytes,omitempty"`
}

const (
	DefaultFileReadTimeout            = 30 * time.Second
	MaxFileReadTimeout                = 60 * time.Second
	FailureKindFileOperationsDisabled = "file_operations_disabled"
	FailureKindFileReadPathInvalid    = "file_read_path_invalid"
	FailureKindFileReadUnavailable    = "file_read_unavailable"
	FailureKindFileReadNotFound       = "file_read_not_found"
	FailureKindFileReadPermission     = "file_read_permission_denied"
	FailureKindFileReadSymlink        = "file_read_symlink_rejected"
	FailureKindFileReadNonRegular     = "file_read_non_regular"
	FailureKindFileReadChanged        = "file_read_changed"
	FailureKindFileReadOffset         = "file_read_offset_out_of_range"
	FailureKindFileReadFailed         = "file_read_failed"
)

type SSHFileReadRequest struct {
	Target   string        `json:"target"`
	Path     string        `json:"path"`
	Offset   int64         `json:"offset,omitempty"`
	MaxBytes int           `json:"max_bytes,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

const (
	DefaultBinaryDeploymentTimeout   = 10 * time.Minute
	MaxBinaryDeploymentTimeout       = 15 * time.Minute
	FailureKindDeploymentUnavailable = "binary_deployment_unavailable"
	FailureKindDeploymentPath        = "binary_deployment_path_invalid"
	FailureKindDeploymentSource      = "binary_deployment_source_invalid"
	FailureKindDeploymentTooLarge    = "binary_deployment_source_too_large"
	FailureKindDeploymentFailed      = "binary_deployment_failed"
	FailureKindDeploymentUnknown     = "binary_deployment_outcome_unknown"
	DeploymentStartNotRequested      = "not_requested"
	DeploymentStartCompleted         = "completed"
	DeploymentStartFailed            = "failed"
	DeploymentStartOutcomeUnknown    = "outcome_unknown"
)

type SSHBinaryDeploymentRequest struct {
	Target      string        `json:"target"`
	SourcePath  string        `json:"source_path,omitempty"`
	RemotePath  string        `json:"remote_path,omitempty"`
	StartAction string        `json:"start_action,omitempty"`
	MaxBytes    int64         `json:"max_bytes,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

type SSHSessionContext = worksession.Context
type SSHWorkSession = worksession.Session

type OpenSSHSessionRequest struct {
	Target string `json:"target"`
}

type SetSSHSessionContextRequest struct {
	SessionID string            `json:"session_id"`
	Context   SSHSessionContext `json:"context"`
}

type ExecuteSSHSessionRequest struct {
	SessionID string        `json:"session_id"`
	Command   string        `json:"command"`
	AsRoot    bool          `json:"as_root,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty"`
	MaxBytes  int           `json:"max_bytes,omitempty"`
}

type SSHSessionResult struct {
	Status   string          `json:"status"`
	Message  string          `json:"message,omitempty"`
	Decision policy.Decision `json:"decision,omitempty"`
	Reason   policy.Reason   `json:"reason,omitempty"`
	Session  *SSHWorkSession `json:"session,omitempty"`
}

type SQLRequest struct {
	Target    string        `json:"target"`
	Database  string        `json:"database,omitempty"`
	Statement string        `json:"statement"`
	Timeout   time.Duration `json:"timeout,omitempty"`
	MaxRows   int           `json:"max_rows,omitempty"`
	MaxBytes  int           `json:"max_bytes,omitempty"`
}

type DatabaseListRequest struct {
	Target string `json:"target"`
}

type SSHOutput struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitStatus      int    `json:"exit_status"`
	OutputTruncated bool   `json:"output_truncated"`
}

type SSHFileOutput struct {
	Path      string                    `json:"path"`
	Offset    int64                     `json:"offset"`
	Content   string                    `json:"content"`
	Encoding  sshtransport.FileEncoding `json:"encoding"`
	BytesRead int                       `json:"bytes_read"`
	FileSize  int64                     `json:"file_size"`
	EOF       bool                      `json:"eof"`
	Truncated bool                      `json:"truncated"`
}

type SSHDeploymentOutput struct {
	RemotePath      string `json:"remote_path"`
	BackupPath      string `json:"backup_path"`
	BytesUploaded   int64  `json:"bytes_uploaded"`
	SHA256          string `json:"sha256"`
	Activated       bool   `json:"activated"`
	StartStatus     string `json:"start_status"`
	StartExitStatus *int   `json:"start_exit_status,omitempty"`
}

type SQLOutput struct {
	Columns           []string             `json:"columns,omitempty"`
	Rows              [][]string           `json:"rows,omitempty"`
	RowsTruncated     bool                 `json:"rows_truncated,omitempty"`
	BytesTruncated    bool                 `json:"bytes_truncated,omitempty"`
	AffectedRows      int64                `json:"affected_rows,omitempty"`
	TransportSecurity dbtransport.Security `json:"transport_security,omitempty"`
}

type Result struct {
	Status                string               `json:"status"`
	ExecutionOutcome      string               `json:"execution_outcome,omitempty"`
	AuditOutcome          string               `json:"audit_outcome,omitempty"`
	FailureKind           string               `json:"failure_kind,omitempty"`
	Message               string               `json:"message,omitempty"`
	Decision              policy.Decision      `json:"decision,omitempty"`
	Reason                policy.Reason        `json:"reason,omitempty"`
	RuleID                string               `json:"rule_id,omitempty"`
	MatchedFragment       string               `json:"matched_fragment,omitempty"`
	HandoffCommand        string               `json:"handoff_command,omitempty"`
	Risk                  policy.Risk          `json:"risk,omitempty"`
	Payload               string               `json:"-"`
	Databases             []string             `json:"databases,omitempty"`
	DatabasesTruncated    bool                 `json:"databases_truncated,omitempty"`
	SSH                   *SSHOutput           `json:"ssh,omitempty"`
	File                  *SSHFileOutput       `json:"file,omitempty"`
	Deployment            *SSHDeploymentOutput `json:"deployment,omitempty"`
	SQL                   *SQLOutput           `json:"sql,omitempty"`
	UntrustedRemoteOutput bool                 `json:"untrusted_remote_output"`
	RemoteExecuted        bool                 `json:"remote_executed,omitempty"`
	AuditWriteFailed      bool                 `json:"audit_write_failed,omitempty"`
	SSHSession            *SSHWorkSession      `json:"ssh_session,omitempty"`
}

func (e *Engine) ListTargets(ctx context.Context) (TargetsResult, error) {
	if e == nil || e.deps.Targets == nil {
		return TargetsResult{}, errors.New("target store is unavailable")
	}
	sshTargets, err := e.deps.Targets.ListSSHTargets(ctx)
	if err != nil {
		return TargetsResult{}, err
	}
	databases, err := e.deps.Targets.ListDatabaseInstances(ctx)
	if err != nil {
		return TargetsResult{}, err
	}
	result := TargetsResult{SSH: make([]SSHTarget, 0, len(sshTargets)), Databases: make([]DatabaseTarget, 0, len(databases))}
	for _, target := range sshTargets {
		allowed := fileOperationsAllowed(target)
		result.SSH = append(result.SSH, SSHTarget{IP: target.IP, Port: target.SSHPort, Description: target.Description, Environment: target.Environment, Enabled: target.Enabled, FileReadAvailable: target.Enabled && allowed, AllowFileOperations: allowed})
	}
	for _, target := range databases {
		result.Databases = append(result.Databases, DatabaseTarget{Target: net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), Engine: target.Engine, Description: target.Description, Environment: target.Environment, Enabled: target.Enabled})
	}
	return result, nil
}

func (e *Engine) DescribeExecutionSpecification(ctx context.Context, request ExecutionSpecificationRequest) (ExecutionSpecification, error) {
	capability := ExecutionSpecification{
		Protocol:             request.Protocol,
		PolicyVersion:        policy.Version,
		DirectExecution:      []string{},
		AbsoluteProhibitions: policy.HardStopRuleIDs(),
		MaxOperationSeconds:  0,
		DefaultOutputBytes:   policy.DefaultMaxBytes,
		MaxOutputBytes:       0,
	}
	switch request.Protocol {
	case ProtocolSSH:
		target, err := e.sshTarget(ctx, request.Target)
		if err != nil {
			return ExecutionSpecification{}, err
		}
		capability.Target = target.IP
		capability.Available = sshTargetAvailable(target)
		if capability.Available {
			capability.DirectExecution = []string{"all_non_blocked_ssh", "as_root_via_daemon_sudo_n"}
		}
		capability.AllowFileOperations = fileOperationsAllowed(target)
		capability.FileReadAvailable = capability.Available && capability.AllowFileOperations
		capability.FileReadDefaultBytes = sshtransport.DefaultFileReadBytes
		capability.FileReadMaxBytes = sshtransport.MaxFileReadBytes
		capability.FileReadDefaultTimeoutSeconds = int(DefaultFileReadTimeout / time.Second)
		capability.FileReadMaxTimeoutSeconds = int(MaxFileReadTimeout / time.Second)
		if capability.FileReadAvailable {
			capability.DirectExecution = append(capability.DirectExecution, "constrained_read_only_file_inspection")
		}
		capability.BinaryDeploymentDefaultBytes = sshtransport.DefaultBinaryDeploymentBytes
		capability.BinaryDeploymentMaxBytes = sshtransport.MaxBinaryDeploymentBytes
		capability.BinaryDeploymentDefaultTimeoutSeconds = int(DefaultBinaryDeploymentTimeout / time.Second)
		capability.BinaryDeploymentMaxTimeoutSeconds = int(MaxBinaryDeploymentTimeout / time.Second)
		if capability.Available && capability.AllowFileOperations {
			capability.BinaryDeploymentAvailable = true
			capability.DirectExecution = append(capability.DirectExecution, "controlled_binary_deployment")
		}
		return capability, nil
	case ProtocolSQL:
		instance, targetID, err := e.lookupDatabaseTarget(ctx, request.Target)
		if err != nil {
			return ExecutionSpecification{}, err
		}
		capability.Target = targetID
		capability.Available = instance.Enabled
		if capability.Available {
			capability.DirectExecution = []string{"all_non_blocked_sql", "write_sql_with_explicit_write_credential"}
		}
		capability.MaxRows = 0
		return capability, nil
	default:
		return ExecutionSpecification{}, fmt.Errorf("unsupported target protocol %q", request.Protocol)
	}
}

func (e *Engine) RunSSH(ctx context.Context, request SSHRequest) (Result, error) {
	target, err := e.sshTarget(ctx, request.Target)
	if err != nil {
		if err := e.openTUIForUnregisteredTarget(err); err != nil {
			return Result{}, err
		}
		return Result{}, err
	}
	if !sshTargetAvailable(target) {
		decision := e.evaluateSSH(ctx, policy.SSHRequest{Command: request.Command, AsRoot: request.AsRoot, Timeout: request.Timeout, MaxBytes: request.MaxBytes, CommandBlacklistPatterns: append([]string(nil), target.CommandBlacklistPatterns...)})
		decision.Decision = policy.DecisionRejected
		decision.Reason = policy.ReasonTargetUnavailable
		decision.RuleID = ""
		decision.MatchedFragment = ""
		decision.Risk = policy.RiskNone
		return e.rejectedResult(ctx, "ssh", target.IP, bindTarget(decision.Payload, "ssh", target.IP), decision)
	}
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		return e.lockedResult(ctx, "ssh", target.IP)
	}
	if err != nil {
		return Result{}, err
	}
	decision := e.evaluateSSH(ctx, policy.SSHRequest{Command: request.Command, AsRoot: request.AsRoot, Timeout: request.Timeout, MaxBytes: request.MaxBytes, CommandBlacklistPatterns: append([]string(nil), target.CommandBlacklistPatterns...)})
	payload := bindTarget(decision.Payload, "ssh", target.IP)
	if decision.Decision == policy.DecisionRejected || decision.Decision == policy.DecisionPermanentlyRejected {
		return e.rejectedResult(ctx, "ssh", target.IP, payload, decision)
	}
	if decision.InteractiveInputRequired {
		return e.interactiveInputResult(ctx, "ssh", target.IP, payload, decision)
	}
	return e.executeSSH(ctx, target, vault, request, decision, payload, "", decision.Normalized, nil, nil, sshExecutionIsolated)
}

// ReadSSHFile performs one bounded, read-only inspection of a regular file
// on an enabled target whose file-operation capability is enabled. It has its
// own timeout and byte budget; no command policy or shell command is reused.
func (e *Engine) ReadSSHFile(ctx context.Context, request SSHFileReadRequest) (Result, error) {
	target, err := e.sshTarget(ctx, request.Target)
	if err != nil {
		if err := e.openTUIForUnregisteredTarget(err); err != nil {
			return Result{}, err
		}
		return Result{}, err
	}
	path := strings.TrimSpace(request.Path)
	maxBytes := request.MaxBytes
	if maxBytes == 0 {
		maxBytes = sshtransport.DefaultFileReadBytes
	}
	timeout := request.Timeout
	if timeout == 0 {
		timeout = DefaultFileReadTimeout
	}
	request.MaxBytes = maxBytes
	request.Timeout = timeout
	decision := policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic, Timeout: timeout, MaxBytes: maxBytes}
	if !target.Enabled {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadUnavailable, "file_read_unavailable")
	}
	if !fileOperationsAllowed(target) {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileOperationsDisabled, "file_operations_disabled")
	}
	if !isCanonicalFileReadPath(path) {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadPathInvalid, "file_read_path_invalid")
	}
	if request.Offset < 0 {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadPathInvalid, "file_read_offset_invalid")
	}
	if maxBytes <= 0 || maxBytes > sshtransport.MaxFileReadBytes {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadPathInvalid, "file_read_byte_limit_invalid")
	}
	if timeout <= 0 || timeout > MaxFileReadTimeout {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadPathInvalid, "file_read_timeout_invalid")
	}
	if e.deps.FileReader == nil {
		return e.fileReadDecision(ctx, target.IP, request, decision, FailureKindFileReadUnavailable, "file_read_unavailable")
	}
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		return e.lockedFileReadResult(ctx, target.IP, request)
	}
	if err != nil {
		return Result{}, err
	}
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	release, err := e.deps.Limiter.Acquire(ctx, policy.DecisionAllowed)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
		}
		return Result{}, err
	}
	defer release()
	releaseLane, err := e.acquireTargetReadLane(ctx, ProtocolSSH, target.IP)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
		}
		return Result{}, err
	}
	defer releaseLane()
	execution, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if execution.Err() != nil {
		return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
	}
	auditFailed := e.auditFileReadStarted(execution, requestID, target.IP, request, decision) != nil
	if execution.Err() != nil {
		return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
	}
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil || execution.Err() != nil {
		return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
	}
	if !barrierLease.BeginDispatch() {
		return e.stoppedBeforeFileRead(ctx, requestID, target.IP, request, decision), nil
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	remote, readErr := e.deps.FileReader.ReadFile(execution, vault, target, path, request.Offset, maxBytes)
	if readErr != nil {
		remoteExecuted := !errors.Is(readErr, sshtransport.ErrNotDispatched) && !errors.Is(readErr, store.ErrTargetChanged)
		status := StatusOutcomeUnknown
		if !remoteExecuted {
			status = StatusNotDispatched
		} else if fileReadKnownFailure(readErr) {
			status = StatusFailed
		}
		if remoteExecuted {
			auditFailed = auditFailed || e.auditFileReadTerminal(ctx, requestID, target.IP, request, decision, status, durationMS(startedAt, e.deps.Now()), nil, status == StatusOutcomeUnknown) != nil
		} else {
			auditFailed = auditFailed || e.auditFileReadTerminal(ctx, requestID, target.IP, request, decision, status, nil, nil, false) != nil
		}
		result := Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, FailureKind: fileReadFailureKind(readErr), Message: ResultMessage(status, fileReadFailureKind(readErr), decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: fileReadPayload(request), RemoteExecuted: remoteExecuted}
		return markAuditFailed(result, auditFailed), nil
	}
	output := &SSHFileOutput{Path: path, Offset: request.Offset, Content: remote.Content, Encoding: remote.Encoding, BytesRead: remote.BytesRead, FileSize: remote.FileSize, EOF: remote.EOF, Truncated: remote.Truncated}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: decision.Decision, Reason: decision.Reason, Payload: fileReadPayload(request), File: output, UntrustedRemoteOutput: true, RemoteExecuted: true}
	auditFailed = auditFailed || e.auditFileReadTerminal(ctx, requestID, target.IP, request, decision, StatusCompleted, durationMS(startedAt, e.deps.Now()), &remote.BytesRead, remote.Truncated) != nil
	return markAuditFailed(result, auditFailed), nil
}

// fileOperationsAllowed is the single target capability gate for dedicated
// remote file APIs. A false value is always authoritative.
func fileOperationsAllowed(target store.SSHTarget) bool {
	return target.AllowFileOperations
}

type deploymentSpec struct {
	RemotePath  string
	StartAction string
}

type deploymentMetadata struct {
	Size   int64
	SHA256 string
}

// DeploySSHBinary deploys a local regular file to an existing remote regular
// file. Source and destination are supplied directly by the caller; the
// target's AllowFileOperations capability is the only local file-operation
// gate. No deployment registration is required.
func (e *Engine) DeploySSHBinary(ctx context.Context, request SSHBinaryDeploymentRequest) (Result, error) {
	target, err := e.sshTarget(ctx, request.Target)
	if err != nil {
		if err := e.openTUIForUnregisteredTarget(err); err != nil {
			return Result{}, err
		}
		return Result{}, err
	}
	maxBytes := request.MaxBytes
	if maxBytes == 0 {
		maxBytes = sshtransport.DefaultBinaryDeploymentBytes
	}
	timeout := request.Timeout
	if timeout == 0 {
		timeout = DefaultBinaryDeploymentTimeout
	}
	request.MaxBytes = maxBytes
	request.Timeout = timeout
	decision := policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic, Timeout: timeout}
	if !target.Enabled {
		return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindDeploymentUnavailable, "deployment_unavailable")
	}
	if !fileOperationsAllowed(target) {
		return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindFileOperationsDisabled, "file_operations_disabled")
	}
	if e.deps.Deployer == nil {
		return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindDeploymentUnavailable, "deployment_unavailable")
	}
	deployment := deploymentSpec{RemotePath: strings.TrimSpace(request.RemotePath), StartAction: strings.TrimSpace(request.StartAction)}
	if deployment.StartAction != "" {
		startDecision := e.evaluateSSH(ctx, policy.SSHRequest{
			Command: deployment.StartAction, Timeout: timeout, MaxBytes: 1024,
			CommandBlacklistPatterns: append([]string(nil), target.CommandBlacklistPatterns...),
		})
		if startDecision.Decision == policy.DecisionRejected || startDecision.Decision == policy.DecisionPermanentlyRejected || startDecision.InteractiveInputRequired {
			return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindDeploymentSource, "start_action_not_allowed")
		}
		deployment.StartAction = startDecision.Normalized
	}
	if deployment.RemotePath == "" || !isCanonicalDeploymentResultPath(deployment.RemotePath) {
		return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindDeploymentPath, "remote_path_invalid")
	}
	if maxBytes <= 0 || maxBytes > sshtransport.MaxBinaryDeploymentBytes || timeout <= 0 || timeout > MaxBinaryDeploymentTimeout {
		failureKind, reason := FailureKindDeploymentSource, "deployment_source_invalid"
		if maxBytes > sshtransport.MaxBinaryDeploymentBytes {
			failureKind, reason = FailureKindDeploymentTooLarge, "deployment_source_too_large"
		}
		return e.deploymentDecision(ctx, target.IP, request, decision, failureKind, reason)
	}
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		return e.lockedDeploymentResult(ctx, target.IP, request)
	}
	if err != nil {
		return Result{}, err
	}

	// Resolve the source before acquiring the remote dispatch barrier.
	var source io.ReadCloser
	var metadata deploymentMetadata
	if strings.TrimSpace(request.SourcePath) != "" {
		source, metadata, err = inspectLocalDeploymentSource(ctx, request.SourcePath, maxBytes)
	} else {
		err = os.ErrInvalid
	}
	if err != nil {
		failureKind, reason := FailureKindDeploymentSource, "deployment_source_unavailable"
		if errors.Is(err, sshtransport.ErrDeploymentSourceTooLarge) {
			failureKind, reason = FailureKindDeploymentTooLarge, "deployment_source_too_large"
		}
		return e.deploymentDecision(ctx, target.IP, request, decision, failureKind, reason)
	}
	defer source.Close()
	if metadata.Size < 0 || metadata.Size > maxBytes || metadata.Size > sshtransport.MaxBinaryDeploymentBytes {
		return e.deploymentDecision(ctx, target.IP, request, decision, FailureKindDeploymentTooLarge, "deployment_source_too_large")
	}

	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	release, err := e.deps.Limiter.Acquire(ctx, policy.DecisionAllowed)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDeployment(ctx, requestID, target.IP, request, decision), nil
		}
		return Result{}, err
	}
	defer release()
	releaseLane, err := e.acquireTargetLane(ctx, ProtocolSSH, target.IP)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDeployment(ctx, requestID, target.IP, request, decision), nil
		}
		return Result{}, err
	}
	defer releaseLane()
	execution, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if execution.Err() != nil {
		return e.stoppedBeforeDeployment(ctx, requestID, target.IP, request, decision), nil
	}
	auditFailed := e.auditDeploymentStarted(execution, requestID, target.IP, request, deployment, metadata, decision) != nil
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil || execution.Err() != nil || !barrierLease.BeginDispatch() {
		return e.stoppedBeforeDeployment(ctx, requestID, target.IP, request, decision), nil
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	remote, deployErr := e.deps.Deployer.DeployBinary(execution, vault, target, source, sshtransport.BinaryDeploymentRequest{
		RemotePath: deployment.RemotePath, ExpectedSize: metadata.Size, ExpectedSHA256: metadata.SHA256, MaxBytes: maxBytes,
	})
	if deployErr != nil {
		remoteExecuted := !errors.Is(deployErr, sshtransport.ErrNotDispatched) && !errors.Is(deployErr, store.ErrTargetChanged)
		status := StatusOutcomeUnknown
		if !remoteExecuted {
			status = StatusNotDispatched
		} else if deploymentKnownFailure(deployErr) {
			status = StatusFailed
		}
		// The transport may have moved the live target into its backup before a
		// later operation failed or its response was lost. Preserve any returned
		// transition metadata in both the caller result and the terminal audit so
		// operators can locate the backup without retrying the deployment.
		output := deploymentOutputIfPresent(deployment, metadata, remote)
		result := Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, FailureKind: deploymentFailureKind(deployErr), Message: ResultMessage(status, deploymentFailureKind(deployErr), decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: remoteExecuted}
		auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, status, durationForRemote(remoteExecuted, startedAt, e.deps.Now()), output) != nil
		return markAuditFailed(result, auditFailed), nil
	}

	output := deploymentOutput(deployment, metadata, remote)
	if !deploymentResultMatchesRequest(remote, deployment, metadata) {
		result := Result{Status: StatusOutcomeUnknown, ExecutionOutcome: StatusOutcomeUnknown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentUnknown, Message: ResultMessage(StatusOutcomeUnknown, FailureKindDeploymentUnknown, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
		auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusOutcomeUnknown, durationMS(startedAt, e.deps.Now()), output) != nil
		return markAuditFailed(result, auditFailed), nil
	}
	if !remote.Activated {
		result := Result{Status: StatusOutcomeUnknown, ExecutionOutcome: StatusOutcomeUnknown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentUnknown, Message: ResultMessage(StatusOutcomeUnknown, FailureKindDeploymentUnknown, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
		auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusOutcomeUnknown, durationMS(startedAt, e.deps.Now()), output) != nil
		return markAuditFailed(result, auditFailed), nil
	}
	if deployment.StartAction != "" {
		if e.deps.SSH == nil {
			// Activation already happened, so this is an unknown post-deploy
			// state. Keep the transition metadata and never claim that the fixed
			// start action ran.
			output.StartStatus = DeploymentStartOutcomeUnknown
			result := Result{Status: StatusOutcomeUnknown, ExecutionOutcome: StatusOutcomeUnknown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentUnknown, Message: ResultMessage(StatusOutcomeUnknown, FailureKindDeploymentUnknown, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
			auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusOutcomeUnknown, durationMS(startedAt, e.deps.Now()), output) != nil
			return markAuditFailed(result, auditFailed), nil
		}
		start, startErr := e.deps.SSH.ExecuteIsolated(execution, vault, target, "direct-binary-deployment-v1", deployment.StartAction, false, 1024)
		if startErr != nil {
			output.StartStatus = DeploymentStartOutcomeUnknown
			result := Result{Status: StatusOutcomeUnknown, ExecutionOutcome: StatusOutcomeUnknown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentUnknown, Message: ResultMessage(StatusOutcomeUnknown, FailureKindDeploymentUnknown, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
			auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusOutcomeUnknown, durationMS(startedAt, e.deps.Now()), output) != nil
			return markAuditFailed(result, auditFailed), nil
		}
		exitStatus := start.ExitStatus
		output.StartExitStatus = &exitStatus
		if start.OutputTruncated {
			output.StartStatus = DeploymentStartOutcomeUnknown
			result := Result{Status: StatusOutcomeUnknown, ExecutionOutcome: StatusOutcomeUnknown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentUnknown, Message: ResultMessage(StatusOutcomeUnknown, FailureKindDeploymentUnknown, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
			auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusOutcomeUnknown, durationMS(startedAt, e.deps.Now()), output) != nil
			return markAuditFailed(result, auditFailed), nil
		}
		if start.ExitStatus != 0 {
			output.StartStatus = DeploymentStartFailed
			result := Result{Status: StatusFailed, ExecutionOutcome: ExecutionOutcomeFailedKnown, AuditOutcome: AuditOutcomeRecorded, FailureKind: FailureKindDeploymentFailed, Message: ResultMessage(StatusFailed, FailureKindDeploymentFailed, decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
			auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusFailed, durationMS(startedAt, e.deps.Now()), output) != nil
			return markAuditFailed(result, auditFailed), nil
		}
		output.StartStatus = DeploymentStartCompleted
	}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: decision.Decision, Reason: decision.Reason, Payload: deploymentPayload(request, deployment, metadata), Deployment: output, RemoteExecuted: true}
	auditFailed = auditFailed || e.auditDeploymentTerminal(ctx, requestID, target.IP, request, deployment, metadata, decision, StatusCompleted, durationMS(startedAt, e.deps.Now()), output) != nil
	return markAuditFailed(result, auditFailed), nil
}

// deploymentResultMatchesRequest is a second trust boundary after the
// replaceable transport interface. A deployer may report success only for the
// exact requested destination and source bytes, and its backup must be a
// distinct canonical sibling path.
func deploymentResultMatchesRequest(remote sshtransport.BinaryDeploymentResult, deployment deploymentSpec, metadata deploymentMetadata) bool {
	if remote.RemotePath != deployment.RemotePath || remote.BytesUploaded != metadata.Size || !strings.EqualFold(remote.SHA256, metadata.SHA256) {
		return false
	}
	backup := remote.BackupPath
	if !isCanonicalDeploymentResultPath(backup) || backup == deployment.RemotePath || path.Dir(backup) != path.Dir(deployment.RemotePath) {
		return false
	}
	return true
}

func deploymentOutput(deployment deploymentSpec, metadata deploymentMetadata, remote sshtransport.BinaryDeploymentResult) *SSHDeploymentOutput {
	return &SSHDeploymentOutput{
		RemotePath: remote.RemotePath,
		BackupPath: remote.BackupPath, BytesUploaded: remote.BytesUploaded,
		SHA256: remote.SHA256, Activated: remote.Activated,
		StartStatus: DeploymentStartNotRequested,
	}
}

func deploymentOutputIfPresent(deployment deploymentSpec, metadata deploymentMetadata, remote sshtransport.BinaryDeploymentResult) *SSHDeploymentOutput {
	if remote.RemotePath == "" && remote.BackupPath == "" && remote.BytesUploaded == 0 && remote.SHA256 == "" && !remote.Activated {
		return nil
	}
	return deploymentOutput(deployment, metadata, remote)
}

func isCanonicalDeploymentResultPath(value string) bool {
	if value == "" || value == "/" || value[0] != '/' || strings.ContainsRune(value, '\x00') || strings.HasSuffix(value, "/") {
		return false
	}
	for index, component := range strings.Split(value, "/") {
		if index > 0 && component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func inspectLocalDeploymentSource(ctx context.Context, sourcePath string, maxBytes int64) (io.ReadCloser, deploymentMetadata, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" || strings.ContainsRune(sourcePath, '\x00') {
		return nil, deploymentMetadata{}, os.ErrInvalid
	}
	info, err := os.Lstat(sourcePath)
	if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, deploymentMetadata{}, os.ErrInvalid
	}
	if maxBytes <= 0 || info.Size() > maxBytes {
		return nil, deploymentMetadata{}, sshtransport.ErrDeploymentSourceTooLarge
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return nil, deploymentMetadata{}, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		_ = file.Close()
		return nil, deploymentMetadata{}, os.ErrInvalid
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, deploymentMetadata{}, err
		}
		read, readErr := file.Read(buffer)
		if read < 0 || read > len(buffer) || total+int64(read) > maxBytes {
			_ = file.Close()
			return nil, deploymentMetadata{}, sshtransport.ErrDeploymentSourceTooLarge
		}
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
			total += int64(read)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil || read == 0 {
			_ = file.Close()
			return nil, deploymentMetadata{}, os.ErrInvalid
		}
	}
	if total != info.Size() {
		_ = file.Close()
		return nil, deploymentMetadata{}, sshtransport.ErrDeploymentIntegrity
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, deploymentMetadata{}, err
	}
	return file, deploymentMetadata{Size: total, SHA256: digest}, nil
}

func deploymentPayload(_ SSHBinaryDeploymentRequest, deployment deploymentSpec, metadata deploymentMetadata) string {
	return fmt.Sprintf("kind=ssh_binary_deployment\nremote_path=%s\nsize=%d\nsha256=%s", deployment.RemotePath, metadata.Size, metadata.SHA256)
}

func deploymentKnownFailure(err error) bool {
	return errors.Is(err, sshtransport.ErrDeploymentTargetNotFound) || errors.Is(err, sshtransport.ErrDeploymentTargetSymlink) || errors.Is(err, sshtransport.ErrDeploymentTargetNotRegular) || errors.Is(err, sshtransport.ErrDeploymentTargetChanged) || errors.Is(err, sshtransport.ErrDeploymentSourceTooLarge) || errors.Is(err, sshtransport.ErrDeploymentIntegrity) || errors.Is(err, sshtransport.ErrDeploymentBackupExists) || errors.Is(err, sshtransport.ErrDeploymentActivationFailed) || errors.Is(err, sshtransport.ErrDeploymentFailed)
}

func deploymentFailureKind(err error) string {
	switch {
	case errors.Is(err, sshtransport.ErrDeploymentSourceTooLarge):
		return FailureKindDeploymentTooLarge
	case errors.Is(err, sshtransport.ErrDeploymentOutcomeUnknown):
		return FailureKindDeploymentUnknown
	case deploymentKnownFailure(err):
		return FailureKindDeploymentFailed
	default:
		return FailureKindDeploymentUnknown
	}
}

func durationForRemote(remote bool, start, end time.Time) *int64 {
	if !remote {
		return nil
	}
	return durationMS(start, end)
}

func (e *Engine) deploymentDecision(ctx context.Context, target string, request SSHBinaryDeploymentRequest, decision policy.Result, failureKind, reason string) (Result, error) {
	decision.Decision, decision.Reason = policy.DecisionRejected, policy.ReasonInvalidRequest
	result := notDispatchedResult(StatusRejected, decision, deploymentPayload(request, deploymentSpec{RemotePath: strings.TrimSpace(request.RemotePath)}, deploymentMetadata{}))
	result.FailureKind = failureKind
	result.Message = ResultMessage(StatusRejected, failureKind, decision.Decision, decision.Reason)
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	return markAuditFailed(result, e.auditDeploymentDecision(ctx, requestID, target, request, decision, reason) != nil), nil
}

func (e *Engine) lockedDeploymentResult(ctx context.Context, target string, request SSHBinaryDeploymentRequest) (Result, error) {
	decision := policy.Result{Decision: policy.DecisionRejected, Reason: policy.ReasonUnlockRequired}
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	result := notDispatchedResult(StatusUnlockRequired, decision, deploymentPayload(request, deploymentSpec{RemotePath: strings.TrimSpace(request.RemotePath)}, deploymentMetadata{}))
	_ = e.openTUI()
	return markAuditFailed(result, e.auditDeploymentDecision(ctx, requestID, target, request, decision, "unlock_required") != nil), nil
}

func (e *Engine) stoppedBeforeDeployment(ctx context.Context, requestID, target string, request SSHBinaryDeploymentRequest, decision policy.Result) Result {
	result := notDispatchedResult(StatusNotDispatched, decision, deploymentPayload(request, deploymentSpec{RemotePath: strings.TrimSpace(request.RemotePath)}, deploymentMetadata{}))
	return markAuditFailed(result, e.auditDeploymentDecision(ctx, requestID, target, request, decision, "not_dispatched") != nil)
}

func (e *Engine) auditDeploymentEvent(ctx context.Context, event auditlog.Event, request SSHBinaryDeploymentRequest, deployment deploymentSpec, metadata deploymentMetadata, output *SSHDeploymentOutput) error {
	event.Action = "ssh_binary_deployment"
	auditDeployment := &auditlog.Deployment{RemotePath: deployment.RemotePath, BytesUploaded: metadata.Size, SHA256: metadata.SHA256}
	if output != nil {
		// Preserve the exact transport-reported transition metadata for terminal
		// forensics, including an inconsistent result that was rejected before
		// any start action. The direct request remains the source of truth for
		// dispatch; this record describes what the transport claimed.
		auditDeployment.RemotePath = output.RemotePath
		auditDeployment.BackupPath = output.BackupPath
		auditDeployment.BytesUploaded = output.BytesUploaded
		auditDeployment.SHA256 = output.SHA256
		auditDeployment.Activated = output.Activated
		auditDeployment.StartStatus = output.StartStatus
	}
	event.Deployment = auditDeployment
	return e.deps.Audit.Record(ctx, event)
}

func backupPath(output *SSHDeploymentOutput) string {
	if output == nil {
		return ""
	}
	return output.BackupPath
}

func startStatus(output *SSHDeploymentOutput) string {
	if output == nil {
		return ""
	}
	return output.StartStatus
}

func (e *Engine) auditDeploymentStarted(ctx context.Context, requestID, target string, request SSHBinaryDeploymentRequest, deployment deploymentSpec, metadata deploymentMetadata, decision policy.Result) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	return e.auditDeploymentEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: auditlog.PhaseStarted, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: string(decision.Reason)}, Result: auditlog.Result{Status: "started"}}, request, deployment, metadata, nil)
}

func (e *Engine) auditDeploymentDecision(ctx context.Context, requestID, target string, request SSHBinaryDeploymentRequest, decision policy.Result, reason string) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	deployment := deploymentSpec{RemotePath: strings.TrimSpace(request.RemotePath)}
	return e.auditDeploymentEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: auditlog.PhaseDecision, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: reason}, Result: auditlog.Result{Status: StatusRejected}}, request, deployment, deploymentMetadata{}, nil)
}

func (e *Engine) auditDeploymentTerminal(ctx context.Context, requestID, target string, request SSHBinaryDeploymentRequest, deployment deploymentSpec, metadata deploymentMetadata, decision policy.Result, status string, duration *int64, output *SSHDeploymentOutput) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	phase := auditlog.PhaseCompleted
	if status != StatusCompleted {
		phase = auditlog.PhaseFailed
	}
	return e.auditDeploymentEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: phase, RemoteExecuted: status != StatusNotDispatched, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: string(decision.Reason)}, Result: auditlog.Result{Status: status, DurationMS: duration}}, request, deployment, metadata, output)
}

func isCanonicalFileReadPath(value string) bool {
	if value == "" || value[0] != '/' || strings.ContainsRune(value, '\x00') || (value != "/" && strings.HasSuffix(value, "/")) {
		return false
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "." || component == ".." || component == "" {
			return false
		}
	}
	return true
}

func fileReadPayload(request SSHFileReadRequest) string {
	return fmt.Sprintf("kind=ssh_file_read\npath=%s\noffset=%d\nmax_bytes=%d", strings.TrimSpace(request.Path), request.Offset, request.MaxBytes)
}

func fileReadKnownFailure(err error) bool {
	return errors.Is(err, sshtransport.ErrFileNotFound) || errors.Is(err, sshtransport.ErrFilePermissionDenied) || errors.Is(err, sshtransport.ErrFileSymlink) || errors.Is(err, sshtransport.ErrFileNotRegular) || errors.Is(err, sshtransport.ErrFileChanged) || errors.Is(err, sshtransport.ErrFileOffsetOutOfRange) || errors.Is(err, sshtransport.ErrFileReadFailed)
}

func fileReadFailureKind(err error) string {
	switch {
	case errors.Is(err, sshtransport.ErrFileNotFound):
		return FailureKindFileReadNotFound
	case errors.Is(err, sshtransport.ErrFilePermissionDenied):
		return FailureKindFileReadPermission
	case errors.Is(err, sshtransport.ErrFileSymlink):
		return FailureKindFileReadSymlink
	case errors.Is(err, sshtransport.ErrFileNotRegular):
		return FailureKindFileReadNonRegular
	case errors.Is(err, sshtransport.ErrFileChanged):
		return FailureKindFileReadChanged
	case errors.Is(err, sshtransport.ErrFileOffsetOutOfRange):
		return FailureKindFileReadOffset
	case errors.Is(err, sshtransport.ErrFileReadFailed):
		return FailureKindFileReadFailed
	default:
		return ""
	}
}

func (e *Engine) fileReadDecision(ctx context.Context, target string, request SSHFileReadRequest, decision policy.Result, failureKind, auditReason string) (Result, error) {
	decision.Decision = policy.DecisionRejected
	decision.Reason = policy.ReasonInvalidRequest
	decision.Payload = fileReadPayload(request)
	result := notDispatchedResult(StatusRejected, decision, decision.Payload)
	result.FailureKind = failureKind
	result.Message = ResultMessage(StatusRejected, failureKind, decision.Decision, decision.Reason)
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	result = markAuditFailed(result, e.auditFileReadDecision(ctx, requestID, target, request, decision, auditReason) != nil)
	return result, nil
}

func (e *Engine) lockedFileReadResult(ctx context.Context, target string, request SSHFileReadRequest) (Result, error) {
	decision := policy.Result{Decision: policy.DecisionRejected, Reason: policy.ReasonUnlockRequired}
	result := notDispatchedResult(StatusUnlockRequired, decision, fileReadPayload(request))
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	result = markAuditFailed(result, e.auditFileReadDecision(ctx, requestID, target, request, decision, "unlock_required") != nil)
	_ = e.openTUI()
	return result, nil
}

func (e *Engine) stoppedBeforeFileRead(ctx context.Context, requestID, target string, request SSHFileReadRequest, decision policy.Result) Result {
	result := notDispatchedResult(StatusNotDispatched, decision, fileReadPayload(request))
	return markAuditFailed(result, e.auditFileReadTerminal(ctx, requestID, target, request, decision, StatusNotDispatched, nil, nil, false) != nil)
}

func (e *Engine) auditFileReadEvent(ctx context.Context, event auditlog.Event, request SSHFileReadRequest, bytesRead *int) error {
	event.Action = "ssh_file_read"
	event.File = &auditlog.FileRead{Path: strings.TrimSpace(request.Path), Offset: request.Offset, BytesRead: bytesRead}
	return e.deps.Audit.Record(ctx, event)
}

func (e *Engine) auditFileReadStarted(ctx context.Context, requestID, target string, request SSHFileReadRequest, decision policy.Result) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	return e.auditFileReadEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: auditlog.PhaseStarted, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: string(decision.Reason)}, Result: auditlog.Result{Status: "started"}}, request, nil)
}

func (e *Engine) auditFileReadDecision(ctx context.Context, requestID, target string, request SSHFileReadRequest, decision policy.Result, reason string) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	return e.auditFileReadEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: auditlog.PhaseDecision, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: reason}, Result: auditlog.Result{Status: StatusRejected}}, request, nil)
}

func (e *Engine) auditFileReadTerminal(ctx context.Context, requestID, target string, request SSHFileReadRequest, decision policy.Result, status string, duration *int64, bytesRead *int, truncated bool) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	phase := auditlog.PhaseCompleted
	if status != StatusCompleted {
		phase = auditlog.PhaseFailed
	}
	return e.auditFileReadEvent(ctx, auditlog.Event{Time: clock.InBeijing(e.deps.Now()), OperationID: requestID, Phase: phase, RemoteExecuted: status != StatusNotDispatched, Target: auditlog.Target{Kind: "ssh", ID: target}, Actor: e.deps.AuditActor, Policy: auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Reason: string(decision.Reason)}, Result: auditlog.Result{Status: status, DurationMS: duration, OutputTruncated: truncated}}, request, bytesRead)
}

func rawSSHSessionStateChange(command string) bool {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return false
	}
	switch strings.ToLower(fields[0]) {
	case "cd", "export", "unset", "alias", "unalias", "set", "umask":
		return true
	default:
		return false
	}
}

func (e *Engine) OpenSSHSession(ctx context.Context, request OpenSSHSessionRequest) (SSHSessionResult, error) {
	target, err := e.sshTarget(ctx, request.Target)
	if err != nil {
		if err := e.openTUIForUnregisteredTarget(err); err != nil {
			return SSHSessionResult{}, err
		}
		return SSHSessionResult{}, err
	}
	if !sshTargetAvailable(target) {
		return e.rejectedSSHSession(ctx, target.IP, StatusRejected, policy.ReasonTargetUnavailable)
	}
	if _, err := e.vault(); err != nil {
		if errors.Is(err, store.ErrLocked) {
			e.deps.WorkSessions.Clear()
			return e.lockedSSHSession(ctx, target.IP)
		}
		return SSHSessionResult{}, err
	}
	session, err := e.openSSHWorkSession(target.IP, target.Revision, policy.Version)
	if err != nil {
		return SSHSessionResult{}, err
	}
	result := SSHSessionResult{Status: StatusSSHSessionOpened, Session: &session}
	if err := e.auditSSHSession(ctx, session.ID, "ssh_session_open", target.IP, StatusSSHSessionOpened, policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic}); err != nil {
		result.Message = "本地审计未写入，但工作会话已创建。"
	}
	return result, nil
}

func (e *Engine) SetSSHSessionContext(ctx context.Context, request SetSSHSessionContextRequest) (SSHSessionResult, error) {
	if err := worksession.ValidateContext(request.Context); err != nil {
		return e.rejectedSSHSession(ctx, "", StatusRejected, policy.ReasonInvalidRequest)
	}
	lease, err := e.acquireSSHSession(request.SessionID)
	if err != nil {
		return e.sshSessionFailure(ctx, request.SessionID, err)
	}
	defer lease.Release()
	session := lease.Session()
	if result, ok, err := e.validateSSHSession(ctx, session); err != nil || !ok {
		return result, err
	}
	updated, err := lease.SetContext(request.Context)
	if err != nil {
		return e.sshSessionFailure(ctx, session.ID, err)
	}
	result := SSHSessionResult{Status: StatusSSHSessionContextUpdated, Session: &updated}
	if err := e.auditSSHSession(ctx, session.ID, "ssh_session_context", session.Target, StatusSSHSessionContextUpdated, policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic}); err != nil {
		result.Message = "本地审计未写入，但工作会话上下文已更新。"
	}
	return result, nil
}

func (e *Engine) ExecuteSSHSession(ctx context.Context, request ExecuteSSHSessionRequest) (Result, error) {
	lease, err := e.acquireSSHSession(request.SessionID)
	if err != nil {
		return e.sshSessionExecutionFailure(ctx, request.SessionID, err)
	}
	defer lease.Release()
	session := lease.Session()
	if result, ok, err := e.validateSSHSession(ctx, session); err != nil || !ok {
		return sessionExecutionResult(result), err
	}
	target, err := e.sshTarget(ctx, session.Target)
	if err != nil {
		return Result{}, err
	}
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		e.deps.WorkSessions.Clear()
		locked, lockErr := e.lockedResult(ctx, "ssh", session.Target)
		return locked, lockErr
	}
	if err != nil {
		return Result{}, err
	}
	decision := e.evaluateSSH(ctx, policy.SSHRequest{Command: request.Command, AsRoot: request.AsRoot, WorkingDirectory: session.Context.WorkingDirectory, Timeout: request.Timeout, MaxBytes: request.MaxBytes, CommandBlacklistPatterns: append([]string(nil), target.CommandBlacklistPatterns...)})
	payload := bindTarget(decision.Payload, "ssh", target.IP) + "\nssh_session_id=" + session.ID
	if decision.Decision == policy.DecisionRejected || decision.Decision == policy.DecisionPermanentlyRejected {
		result, resultErr := e.rejectedResult(ctx, "ssh", target.IP, payload, decision)
		return withSSHSessionHardStopHandoff(result, decision, session.Context), resultErr
	}
	if decision.InteractiveInputRequired {
		result, resultErr := e.interactiveInputResult(ctx, "ssh", target.IP, payload, decision)
		if resultErr == nil {
			result.SSHSession = &session
		}
		return result, resultErr
	}
	remoteCommand := session.Context.WrapCommand(decision.Normalized)
	result, err := e.executeSSH(ctx, target, vault, SSHRequest{Target: target.IP, Command: request.Command, AsRoot: request.AsRoot, Timeout: request.Timeout, MaxBytes: request.MaxBytes}, decision, payload, "", remoteCommand, lease.BeginDispatch, lease.FinishDispatch, sshExecutionDedicated)
	if err != nil {
		return result, err
	}
	switch result.Status {
	case StatusCompleted:
		accepted := lease.Accept()
		if accepted.ID != "" {
			result.SSHSession = &accepted
		}
	case StatusAuditWriteFailed:
		if result.RemoteExecuted {
			e.invalidateSSHWorkSession(session.ID)
			break
		}
		accepted := lease.Accept()
		if accepted.ID != "" {
			result.SSHSession = &accepted
		}
	case StatusOutcomeUnknown, StatusNotDispatched:
		e.invalidateSSHWorkSession(session.ID)
	}
	return result, nil
}

func withSSHSessionHardStopHandoff(result Result, decision policy.Result, sessionContext SSHSessionContext) Result {
	if decision.Decision != policy.DecisionPermanentlyRejected || result.HandoffCommand == "" {
		return result
	}
	result.HandoffCommand = redactHandoff(sessionContext.WrapCommand(decision.Normalized))
	result.Message = hardStopMessage(decision, result.MatchedFragment, result.HandoffCommand)
	return result
}

func (e *Engine) CloseSSHSession(ctx context.Context, sessionID string) (SSHSessionResult, error) {
	session, found := e.invalidateSSHWorkSession(sessionID)
	if !found {
		return SSHSessionResult{Status: StatusSSHSessionClosed}, nil
	}
	result := SSHSessionResult{Status: StatusSSHSessionClosed}
	if err := e.auditSSHSession(ctx, session.ID, "ssh_session_close", session.Target, StatusSSHSessionClosed, policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic}); err != nil {
		result.Message = "本地审计未写入，但工作会话已关闭。"
	}
	return result, nil
}

func (e *Engine) invalidateSSHWorkSession(sessionID string) (SSHWorkSession, bool) {
	session, err := e.closeSSHWorkSession(sessionID)
	return session, err == nil
}

func (e *Engine) executeSSH(ctx context.Context, target store.SSHTarget, vault *store.Vault, request SSHRequest, decision policy.Result, payload, operationID, remoteCommand string, beforeDispatch func() bool, finishDispatch func(), scope sshExecutionScope) (Result, error) {
	requestID := operationID
	if requestID == "" {
		var err error
		requestID, err = newID()
		if err != nil {
			return Result{}, err
		}
	}
	release, err := e.deps.Limiter.Acquire(ctx, decision.Decision)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
		}
		return Result{}, err
	}
	defer release()
	releaseLane, laneErr := e.acquireTargetReadLane(ctx, ProtocolSSH, target.IP)
	if laneErr != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
		}
		return Result{}, laneErr
	}
	defer releaseLane()
	execution, cancel := context.WithTimeout(ctx, decision.Timeout)
	defer cancel()
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	auditFailed := e.auditStarted(execution, requestID, "ssh", target.IP, decision.Normalized, "", payload, decision) != nil
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	if beforeDispatch != nil && !beforeDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	if finishDispatch != nil {
		defer finishDispatch()
	}
	if !barrierLease.BeginDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "ssh", target.IP, payload, decision), nil
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	var remote sshtransport.ExecutionResult
	// A literal sudo is accepted as an ordinary privileged command, but the
	// transport must still make its outer escalation non-interactive.
	asRoot := request.AsRoot || decision.UseNonInteractiveSudo
	if scope == sshExecutionIsolated {
		remote, err = e.deps.SSH.ExecuteIsolated(execution, vault, target, policy.Version, remoteCommand, asRoot, decision.MaxBytes)
	} else {
		remote, err = e.deps.SSH.Execute(execution, vault, target, remoteCommand, asRoot, decision.MaxBytes)
	}
	if err != nil {
		remoteExecuted := remoteExecutionStarted(err)
		var duration *int64
		if remoteExecuted {
			duration = durationMS(startedAt, e.deps.Now())
		}
		summary := StatusOutcomeUnknown
		status := StatusOutcomeUnknown
		if !remoteExecuted {
			summary = StatusNotDispatched
			status = StatusNotDispatched
		}
		auditFailed = auditFailed || e.auditTerminal(ctx, requestID, "ssh", target.IP, payload, string(decision.Decision), "", nil, nil, duration, summary) != nil
		result := Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, RemoteExecuted: remoteExecuted}
		return markAuditFailed(result, auditFailed), nil
	}
	output := &SSHOutput{Stdout: remote.Stdout, Stderr: remote.Stderr, ExitStatus: remote.ExitStatus, OutputTruncated: remote.OutputTruncated}
	status, phase := StatusCompleted, auditlog.PhaseCompleted
	if remote.OutputTruncated {
		status, phase = StatusOutcomeUnknown, auditlog.PhaseFailed
	}
	result := Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, SSH: output, UntrustedRemoteOutput: true, RemoteExecuted: true}
	exitStatus := remote.ExitStatus
	auditFailed = auditFailed || e.auditFinalTerminal(ctx, requestID, "ssh", target.IP, payload, decision, phase, auditlog.Result{
		Status: status, ExitStatus: &exitStatus, DurationMS: durationMS(startedAt, e.deps.Now()), OutputTruncated: remote.OutputTruncated,
	}) != nil
	return markAuditFailed(result, auditFailed), nil
}

func (e *Engine) ListDatabases(ctx context.Context, request DatabaseListRequest) (Result, error) {
	instance, targetID, err := e.databaseTarget(ctx, request.Target)
	if err != nil {
		return Result{}, err
	}
	authorization := e.acquireDatabaseAuthorization(targetID)
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		return e.lockedResult(ctx, "database", targetID)
	}
	if err != nil {
		return Result{}, err
	}
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	listDecision := policy.Result{Decision: policy.DecisionAllowed, Reason: policy.ReasonDiagnostic, Timeout: policy.DefaultSQLTimeout}
	release, err := e.deps.Limiter.Acquire(ctx, policy.DecisionAllowed)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
		}
		return Result{}, err
	}
	defer release()
	execution, cancel := context.WithTimeout(ctx, policy.DefaultSQLTimeout)
	defer cancel()
	releaseLane, laneErr := e.acquireTargetReadLane(execution, ProtocolSQL, targetID)
	if laneErr != nil {
		if execution.Err() != nil {
			return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
		}
		return Result{}, laneErr
	}
	defer releaseLane()
	if !authorization.available() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
	}
	auditFailed := e.auditStarted(execution, requestID, "database", targetID, "", "", "kind=list_databases", listDecision) != nil
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
	}
	if execution.Err() != nil || !authorization.beginDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
	}
	defer authorization.finishDispatch()
	if !barrierLease.BeginDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, "kind=list_databases", listDecision), nil
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	databases, err := e.deps.Database.ListDatabases(execution, vault, instance)
	if err != nil {
		remoteExecuted := remoteExecutionStarted(err)
		var duration *int64
		if remoteExecuted {
			duration = durationMS(startedAt, e.deps.Now())
		}
		status := StatusOutcomeUnknown
		if !remoteExecuted {
			status = StatusNotDispatched
		}
		auditFailed = auditFailed || e.auditTerminal(ctx, requestID, "database", targetID, "kind=list_databases", string(policy.DecisionAllowed), string(databases.TransportSecurity), nil, nil, duration, status) != nil
		return markAuditFailed(Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", policy.DecisionAllowed, ""), Decision: policy.DecisionAllowed, RemoteExecuted: remoteExecuted}, auditFailed), nil
	}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: policy.DecisionAllowed, Databases: databases.Databases, DatabasesTruncated: databases.OutputTruncated, UntrustedRemoteOutput: true, RemoteExecuted: true}
	auditFailed = auditFailed || e.auditFinalTerminal(ctx, requestID, "database", targetID, "kind=list_databases", listDecision, auditlog.PhaseCompleted, auditlog.Result{
		Status: StatusCompleted, DurationMS: durationMS(startedAt, e.deps.Now()), OutputTruncated: databases.OutputTruncated, TransportSecurity: string(databases.TransportSecurity),
	}) != nil
	return markAuditFailed(result, auditFailed), nil
}

func (e *Engine) RunSQL(ctx context.Context, request SQLRequest) (Result, error) {
	instance, targetID, err := e.databaseTarget(ctx, request.Target)
	if err != nil {
		return Result{}, err
	}
	authorization := e.acquireDatabaseAuthorization(targetID)
	database := strings.TrimSpace(request.Database)
	if database == "" {
		database = instance.DefaultDatabase
	}
	decision := e.evaluateSQL(policy.SQLRequest{Engine: instance.Engine, Statement: request.Statement, Timeout: request.Timeout, MaxRows: request.MaxRows, MaxBytes: request.MaxBytes})
	payload := bindTarget(decision.Payload, "database", targetID) + "\ndatabase=" + database
	if !instance.Enabled || !authorization.available() {
		decision.Decision = policy.DecisionRejected
		decision.Reason = policy.ReasonTargetUnavailable
		return e.rejectedResult(ctx, "database", targetID, payload, decision)
	}
	if decision.Decision == policy.DecisionRejected || decision.Decision == policy.DecisionPermanentlyRejected {
		return e.rejectedResult(ctx, "database", targetID, payload, decision)
	}
	vault, err := e.vault()
	if errors.Is(err, store.ErrLocked) {
		return e.lockedResult(ctx, "database", targetID)
	}
	if err != nil {
		return Result{}, err
	}
	if decision.ExecutionClass != policy.SQLExecutionRead {
		releaseLane, laneErr := e.acquireTargetLane(ctx, ProtocolSQL, targetID)
		if laneErr != nil {
			return Result{}, laneErr
		}
		defer releaseLane()
		return e.executeSQLScript(ctx, instance, targetID, vault, SQLRequest{
			Target: request.Target, Database: database, Statement: request.Statement,
			Timeout: request.Timeout, MaxRows: request.MaxRows, MaxBytes: request.MaxBytes,
		}, decision, payload, "", authorization)
	}
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	stoppedBeforeDispatch := func() (Result, error) {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	release, err := e.deps.Limiter.Acquire(ctx, decision.Decision)
	if err != nil {
		if ctx.Err() != nil {
			return stoppedBeforeDispatch()
		}
		return Result{}, err
	}
	defer release()
	releaseLane, laneErr := e.acquireTargetReadLane(ctx, ProtocolSQL, targetID)
	if laneErr != nil {
		if ctx.Err() != nil {
			return stoppedBeforeDispatch()
		}
		return Result{}, laneErr
	}
	defer releaseLane()
	execution, cancel := context.WithTimeout(ctx, decision.Timeout)
	defer cancel()
	if execution.Err() != nil {
		return stoppedBeforeDispatch()
	}
	auditFailed := e.auditStarted(execution, requestID, "database", targetID, "", decision.Normalized, payload, decision) != nil
	if execution.Err() != nil {
		return stoppedBeforeDispatch()
	}
	statements := sqlStatementsForDispatch(instance.Engine, decision.Normalized)
	if execution.Err() != nil {
		return stoppedBeforeDispatch()
	}
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil {
		return stoppedBeforeDispatch()
	}
	if !authorization.beginDispatch() {
		return stoppedBeforeDispatch()
	}
	defer authorization.finishDispatch()
	if !barrierLease.BeginDispatch() {
		return stoppedBeforeDispatch()
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	var remote dbtransport.QueryResult
	for _, statement := range statements {
		remote, err = e.deps.Database.Query(execution, vault, instance, database, statement, dbtransport.Limits{MaxRows: decision.MaxRows, MaxBytes: decision.MaxBytes})
		if err != nil {
			if failureKind := dbtransport.KnownFailureKind(err); failureKind != "" {
				result, resultErr := e.knownSQLFailure(ctx, requestID, startedAt, targetID, payload, decision, failureKind)
				return markAuditFailed(result, auditFailed), resultErr
			}
			remoteExecuted := remoteExecutionStarted(err)
			var duration *int64
			if remoteExecuted {
				duration = durationMS(startedAt, e.deps.Now())
			}
			summary := StatusOutcomeUnknown
			status := StatusOutcomeUnknown
			if !remoteExecuted {
				summary = StatusNotDispatched
				status = StatusNotDispatched
			}
			auditFailed = auditFailed || e.auditTerminal(ctx, requestID, "database", targetID, payload, string(decision.Decision), "", nil, nil, duration, summary) != nil
			return markAuditFailed(Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, RemoteExecuted: remoteExecuted}, auditFailed), nil
		}
	}
	output := &SQLOutput{Columns: remote.Columns, Rows: cloneRows(remote.Rows), RowsTruncated: remote.RowsTruncated, BytesTruncated: remote.BytesTruncated, TransportSecurity: remote.TransportSecurity}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: decision.Decision, Reason: decision.Reason, Payload: payload, SQL: output, UntrustedRemoteOutput: true, RemoteExecuted: true}
	auditFailed = auditFailed || e.auditFinalTerminal(ctx, requestID, "database", targetID, payload, decision, auditlog.PhaseCompleted, auditlog.Result{
		Status: StatusCompleted, DurationMS: durationMS(startedAt, e.deps.Now()), OutputTruncated: remote.BytesTruncated,
		RowsTruncated: remote.RowsTruncated, TransportSecurity: string(remote.TransportSecurity),
	}) != nil
	return markAuditFailed(result, auditFailed), nil
}

func (e *Engine) knownSQLFailure(ctx context.Context, requestID string, startedAt time.Time, targetID, payload string, decision policy.Result, failureKind string) (Result, error) {
	result := Result{
		Status:           StatusFailed,
		ExecutionOutcome: ExecutionOutcomeFailedKnown,
		AuditOutcome:     AuditOutcomeRecorded,
		FailureKind:      failureKind,
		Message:          ResultMessage(StatusFailed, failureKind, decision.Decision, decision.Reason),
		Decision:         decision.Decision,
		Reason:           decision.Reason,
		Risk:             decision.Risk,
		Payload:          payload,
		RemoteExecuted:   true,
	}
	if err := e.auditFinalTerminal(ctx, requestID, "database", targetID, payload, decision, auditlog.PhaseFailed, auditlog.Result{
		Status: StatusFailed, DurationMS: durationMS(startedAt, e.deps.Now()), Summary: "failure_kind=" + failureKind,
	}); err != nil {
		return markAuditFailed(result, true), nil
	}
	return result, nil
}

func (e *Engine) executeSQLScript(ctx context.Context, instance store.DatabaseInstance, targetID string, vault *store.Vault, request SQLRequest, decision policy.Result, payload, operationID string, authorization databaseAuthorizationLease) (Result, error) {
	requestID := operationID
	if requestID == "" {
		var err error
		requestID, err = newID()
		if err != nil {
			return Result{}, err
		}
	}
	release, err := e.deps.Limiter.Acquire(ctx, policy.DecisionAllowed)
	if err != nil {
		if ctx.Err() != nil {
			return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
		}
		return Result{}, err
	}
	defer release()
	execution, cancel := context.WithTimeout(ctx, decision.Timeout)
	defer cancel()
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	statements := sqlStatementsForDispatch(instance.Engine, decision.Normalized)
	canonical := strings.Join(statements, ";\n")
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	auditFailed := e.auditStarted(execution, requestID, "database", targetID, "", canonical, payload, decision) != nil
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	barrierLease := e.deps.DispatchBarrier.Acquire()
	if barrierLease == nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	if execution.Err() != nil {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	if !authorization.beginDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	defer authorization.finishDispatch()
	if !barrierLease.BeginDispatch() {
		return e.stoppedBeforeDispatchResult(ctx, requestID, "database", targetID, payload, decision), nil
	}
	defer barrierLease.FinishDispatch()
	e.deps.Sessions.TouchRemoteActivity()
	startedAt := e.deps.Now()
	if decision.ExecutionClass == policy.SQLExecutionRead {
		result, resultErr := e.executeSQLQuery(ctx, execution, requestID, startedAt, instance, vault, request.Database, statements[0], targetID, payload, decision)
		return markAuditFailed(result, auditFailed), resultErr
	}
	remote, err := e.deps.Database.ExecuteStatements(execution, vault, instance, request.Database, statements)
	if err != nil {
		if errors.Is(err, store.ErrWriteCredentialNotConfigured) {
			auditFailed = auditFailed || e.auditTerminal(ctx, requestID, "database", targetID, payload, string(decision.Decision), "", nil, nil, nil, "failure_kind="+FailureKindWriteCredential) != nil
			result := notDispatchedResult(StatusNotDispatched, decision, payload)
			result.FailureKind = FailureKindWriteCredential
			result.Message = ResultMessage(result.Status, result.FailureKind, decision.Decision, decision.Reason)
			return markAuditFailed(result, auditFailed), nil
		}
		if failureKind := dbtransport.KnownFailureKind(err); failureKind != "" {
			result, resultErr := e.knownSQLFailure(ctx, requestID, startedAt, targetID, payload, decision, failureKind)
			return markAuditFailed(result, auditFailed), resultErr
		}
		remoteExecuted := remoteExecutionStarted(err)
		var duration *int64
		if remoteExecuted {
			duration = durationMS(startedAt, e.deps.Now())
		}
		status := StatusOutcomeUnknown
		summary := StatusOutcomeUnknown
		if !remoteExecuted {
			status = StatusNotDispatched
			summary = StatusNotDispatched
		}
		auditFailed = auditFailed || e.auditTerminal(ctx, requestID, "database", targetID, payload, string(decision.Decision), "", nil, nil, duration, summary) != nil
		return markAuditFailed(Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, RemoteExecuted: remoteExecuted}, auditFailed), nil
	}
	output := &SQLOutput{AffectedRows: remote.AffectedRows, TransportSecurity: remote.TransportSecurity}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, SQL: output, UntrustedRemoteOutput: true, RemoteExecuted: true}
	affectedRows := remote.AffectedRows
	auditFailed = auditFailed || e.auditFinalTerminal(ctx, requestID, "database", targetID, payload, decision, auditlog.PhaseCompleted, auditlog.Result{
		Status: StatusCompleted, AffectedRows: &affectedRows, DurationMS: durationMS(startedAt, e.deps.Now()), TransportSecurity: string(remote.TransportSecurity),
	}) != nil
	return markAuditFailed(result, auditFailed), nil
}

func (e *Engine) executeSQLQuery(ctx, execution context.Context, requestID string, startedAt time.Time, instance store.DatabaseInstance, vault *store.Vault, database, statement, targetID, payload string, decision policy.Result) (Result, error) {
	remote, err := e.deps.Database.Query(execution, vault, instance, database, statement, dbtransport.Limits{MaxRows: decision.MaxRows, MaxBytes: decision.MaxBytes})
	if err != nil {
		if failureKind := dbtransport.KnownFailureKind(err); failureKind != "" {
			return e.knownSQLFailure(ctx, requestID, startedAt, targetID, payload, decision, failureKind)
		}
		remoteExecuted := remoteExecutionStarted(err)
		var duration *int64
		if remoteExecuted {
			duration = durationMS(startedAt, e.deps.Now())
		}
		status := StatusOutcomeUnknown
		summary := StatusOutcomeUnknown
		if !remoteExecuted {
			status = StatusNotDispatched
			summary = StatusNotDispatched
		}
		auditFailed := e.auditTerminal(ctx, requestID, "database", targetID, payload, string(decision.Decision), "", nil, nil, duration, summary) != nil
		return markAuditFailed(Result{Status: status, ExecutionOutcome: executionOutcomeForStatus(status), AuditOutcome: AuditOutcomeRecorded, Message: ResultMessage(status, "", decision.Decision, decision.Reason), Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, RemoteExecuted: remoteExecuted}, auditFailed), nil
	}
	output := &SQLOutput{Columns: remote.Columns, Rows: cloneRows(remote.Rows), RowsTruncated: remote.RowsTruncated, BytesTruncated: remote.BytesTruncated, TransportSecurity: remote.TransportSecurity}
	result := Result{Status: StatusCompleted, ExecutionOutcome: StatusCompleted, AuditOutcome: AuditOutcomeRecorded, Decision: decision.Decision, Reason: decision.Reason, Risk: decision.Risk, Payload: payload, SQL: output, UntrustedRemoteOutput: true, RemoteExecuted: true}
	auditFailed := e.auditFinalTerminal(ctx, requestID, "database", targetID, payload, decision, auditlog.PhaseCompleted, auditlog.Result{
		Status: StatusCompleted, DurationMS: durationMS(startedAt, e.deps.Now()), OutputTruncated: remote.BytesTruncated,
		RowsTruncated: remote.RowsTruncated, TransportSecurity: string(remote.TransportSecurity),
	}) != nil
	return markAuditFailed(result, auditFailed), nil
}

func (e *Engine) vault() (*store.Vault, error) {
	if e == nil || e.deps.Sessions == nil {
		return nil, store.ErrLocked
	}
	return e.deps.Sessions.Vault()
}

func (e *Engine) lockedResult(ctx context.Context, targetKind, targetID string) (Result, error) {
	decision := policy.Result{Decision: policy.DecisionRejected, Reason: policy.ReasonUnlockRequired}
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	auditErr := e.auditDecision(ctx, requestID, targetKind, targetID, "", decision, StatusUnlockRequired)
	_ = e.openTUI()
	return withAuditFailure(notDispatchedResult(StatusUnlockRequired, decision, ""), auditErr), nil
}

func (e *Engine) acquireSSHSession(sessionID string) (*worksession.Lease, error) {
	return e.acquireSSHSessionContext(context.Background(), sessionID)
}

func (e *Engine) acquireDatabaseAuthorization(target string) databaseAuthorizationLease {
	if e == nil || e.deps.DatabaseAuthorizer == nil {
		return databaseAuthorizationLease{}
	}
	return databaseAuthorizationLease{managed: true, lease: e.deps.DatabaseAuthorizer.acquireTarget(target)}
}

func (e *Engine) acquireSSHSessionContext(ctx context.Context, sessionID string) (*worksession.Lease, error) {
	if e == nil || e.deps.WorkSessions == nil {
		return nil, worksession.ErrSessionInvalidated
	}
	if ownerID := e.executionOwner(); ownerID != "" {
		return e.deps.WorkSessions.AcquireContextForOwner(ctx, ownerID, sessionID)
	}
	return e.deps.WorkSessions.AcquireContext(ctx, sessionID)
}

func (e *Engine) executionOwner() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.deps.ExecutionOwner)
}

func (e *Engine) openSSHWorkSession(target string, revision int64, policyVersion string) (SSHWorkSession, error) {
	if ownerID := e.executionOwner(); ownerID != "" {
		return e.deps.WorkSessions.OpenForOwner(ownerID, target, revision, policyVersion)
	}
	return e.deps.WorkSessions.Open(target, revision, policyVersion)
}

func (e *Engine) closeSSHWorkSession(sessionID string) (SSHWorkSession, error) {
	if e == nil || e.deps.WorkSessions == nil {
		return SSHWorkSession{}, worksession.ErrSessionNotFound
	}
	if ownerID := e.executionOwner(); ownerID != "" {
		return e.deps.WorkSessions.CloseForOwner(ownerID, sessionID)
	}
	session, found := e.deps.WorkSessions.Close(sessionID)
	if !found {
		return SSHWorkSession{}, worksession.ErrSessionNotFound
	}
	return session, nil
}

func (e *Engine) validateSSHSession(ctx context.Context, session SSHWorkSession) (SSHSessionResult, bool, error) {
	target, err := e.sshTarget(ctx, session.Target)
	if err != nil || !sshTargetAvailable(target) || target.Revision != session.TargetRevision || session.PolicyVersion != policy.Version {
		e.deps.WorkSessions.ClearTarget(session.Target)
		result, rejectedErr := e.rejectedSSHSession(ctx, session.Target, StatusSSHSessionInvalidated, policy.ReasonTargetUnavailable)
		return result, false, rejectedErr
	}
	if _, err := e.vault(); err != nil {
		if errors.Is(err, store.ErrLocked) {
			e.deps.WorkSessions.Clear()
			result, lockErr := e.lockedSSHSession(ctx, session.Target)
			return result, false, lockErr
		}
		return SSHSessionResult{}, false, err
	}
	return SSHSessionResult{}, true, nil
}

func (e *Engine) rejectedSSHSession(ctx context.Context, target, status string, reason policy.Reason) (SSHSessionResult, error) {
	decision := policy.Result{Decision: policy.DecisionRejected, Reason: reason}
	requestID, err := newID()
	if err != nil {
		return SSHSessionResult{}, err
	}
	result := sshSessionStatusResult(status, decision)
	if e.auditSSHSession(ctx, requestID, "ssh_session", target, status, decision) != nil {
		result.Message += " 本地审计未写入，但不影响该状态。"
	}
	return result, nil
}

func (e *Engine) lockedSSHSession(ctx context.Context, target string) (SSHSessionResult, error) {
	result, err := e.rejectedSSHSession(ctx, target, StatusUnlockRequired, policy.ReasonUnlockRequired)
	if err != nil {
		return result, err
	}
	_ = e.openTUI()
	return result, nil
}

func (e *Engine) sshSessionFailure(ctx context.Context, sessionID string, failure error) (SSHSessionResult, error) {
	status := StatusSSHSessionInvalidated
	if errors.Is(failure, worksession.ErrSessionNotFound) || errors.Is(failure, worksession.ErrSessionOwnerMismatch) || errors.Is(failure, worksession.ErrInvalidSession) {
		status = StatusSSHSessionNotFound
	}
	if errors.Is(failure, worksession.ErrSessionExpired) {
		status = StatusSSHSessionExpired
	}
	return e.rejectedSSHSession(ctx, sessionID, status, policy.ReasonInvalidRequest)
}

func (e *Engine) sshSessionExecutionFailure(ctx context.Context, sessionID string, failure error) (Result, error) {
	result, err := e.sshSessionFailure(ctx, sessionID, failure)
	return sessionExecutionResult(result), err
}

func (e *Engine) auditSSHSession(ctx context.Context, sessionID, action, target, status string, decision policy.Result) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	return e.deps.Audit.Record(ctx, auditlog.Event{
		Time:        clock.InBeijing(e.deps.Now()),
		OperationID: sessionID,
		Phase:       auditlog.PhaseDecision,
		Action:      action,
		Actor:       e.deps.AuditActor,
		Target:      auditlog.Target{Kind: "ssh", ID: target},
		Policy:      auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Risk: string(decision.Risk), Reason: string(decision.Reason)},
		Result:      auditlog.Result{Status: status},
	})
}

func (e *Engine) rejectedResult(ctx context.Context, targetKind, targetID, payload string, decision policy.Result) (Result, error) {
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	return withAuditFailure(notDispatchedResult(StatusRejected, decision, payload), e.auditDecision(ctx, requestID, targetKind, targetID, payload, decision, StatusRejected)), nil
}

// stoppedBeforeDispatchResult records a best-effort audit event without
// turning an already-known non-dispatch outcome into an audit failure.
func (e *Engine) stoppedBeforeDispatchResult(ctx context.Context, requestID, targetKind, targetID, payload string, decision policy.Result) Result {
	return withAuditFailure(
		notDispatchedResult(StatusNotDispatched, decision, payload),
		e.auditStoppedBeforeDispatch(ctx, requestID, targetKind, targetID, payload, decision.Decision),
	)
}

func (e *Engine) interactiveInputResult(ctx context.Context, targetKind, targetID, payload string, decision policy.Result) (Result, error) {
	requestID, err := newID()
	if err != nil {
		return Result{}, err
	}
	result := notDispatchedResult(StatusInteractiveInputRequired, decision, payload)
	result.HandoffCommand = redactHandoff(decision.Normalized)
	result.Message = "该命令需要交互式终端输入，SSH MCP 的非交互协议不能派发。请由人工在终端执行：" + result.HandoffCommand
	return withAuditFailure(result, e.auditDecision(ctx, requestID, targetKind, targetID, payload, decision, StatusInteractiveInputRequired)), nil
}

var (
	handoffAssignmentSecret = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key)\b(\s*=\s*)("[^"]*"|'[^']*'|\S+)`)
	handoffSQLSecret        = regexp.MustCompile(`(?i)\b(identified\s+by\s+)("[^"]*"|'[^']*'|\S+)`)
)

// notDispatchedResult 统一表达远端尚未派发的本地决定。固定硬拦截会携带
// 可供人工在 MCP 外执行的脱敏命令；目标命令黑名单则不会提供绕过提示。
func notDispatchedResult(status string, decision policy.Result, payload string) Result {
	result := Result{
		Status:           status,
		ExecutionOutcome: StatusNotDispatched,
		AuditOutcome:     AuditOutcomeRecorded,
		Message:          ResultMessage(status, "", decision.Decision, decision.Reason),
		Decision:         decision.Decision,
		Reason:           decision.Reason,
		Risk:             decision.Risk,
		Payload:          payload,
	}
	if decision.Reason == policy.ReasonTargetCommandBlacklist {
		result.RuleID = decision.RuleID
		result.MatchedFragment = redactHandoff(decision.MatchedFragment)
		result.Message = targetCommandBlacklistMessage(result.MatchedFragment)
	} else if decision.RuleID != "" {
		result.RuleID = decision.RuleID
		result.MatchedFragment = redactHandoff(decision.MatchedFragment)
		result.HandoffCommand = redactHandoff(decision.Normalized)
		result.Message = hardStopMessage(decision, result.MatchedFragment, result.HandoffCommand)
	}
	return result
}

func targetCommandBlacklistMessage(matchedPattern string) string {
	message := "命中此 SSH 目标的命令黑名单，操作未派发。"
	if matchedPattern != "" {
		message += " 命中正则：" + matchedPattern + "。"
	}
	message += " 当前用户请求任务链内，AI 不得为达成同一效果改写、变形或重试命令；无关操作可以继续。只有当前本地用户可在本地 TUI 明确调整该目标的命令黑名单，调整后才能提交新的请求重新裁决。"
	return message
}

func redactHandoff(value string) string {
	value = handoffAssignmentSecret.ReplaceAllString(value, "$1$2***")
	return handoffSQLSecret.ReplaceAllString(value, "$1***")
}

func hardStopMessage(decision policy.Result, matchedFragment, handoffCommand string) string {
	message := fmt.Sprintf("命中硬拦截规则 %s，操作未派发。", decision.RuleID)
	if matchedFragment != "" {
		message += " 命中内容：" + matchedFragment + "。"
	}
	message += " 当前用户请求任务链内，AI 不得为达成同一效果改写、变形或重试命令；无关操作可以继续。"
	if handoffCommand != "" {
		message += " 以下已脱敏请求仅供人工在 MCP 外复核并执行：" + handoffCommand
	}
	return message
}

func withAuditFailure(result Result, auditErr error) Result {
	return markAuditFailed(result, auditErr != nil)
}

func markAuditFailed(result Result, failed bool) Result {
	if !failed {
		return result
	}
	result.AuditOutcome = AuditOutcomeFailed
	result.AuditWriteFailed = true
	const suffix = "本地审计未写入，但不影响本次执行结果。"
	if result.Message == "" {
		result.Message = suffix
	} else if !strings.Contains(result.Message, suffix) {
		result.Message += " " + suffix
	}
	return result
}

// sessionExecutionResult 将会话层的拒绝或审计失败映射为未派发的执行结果。
func sessionExecutionResult(session SSHSessionResult) Result {
	decision := policy.Result{Decision: session.Decision, Reason: session.Reason}
	if session.Status == StatusAuditWriteFailed {
		return auditWriteFailureResult(decision, "", false)
	}
	result := notDispatchedResult(session.Status, decision, "")
	if session.Message != "" {
		result.Message = session.Message
	}
	return result
}

func (e *Engine) openTUI() error {
	if e.deps.OpenTUI == nil {
		return errors.New("local TUI is unavailable")
	}
	return e.deps.OpenTUI()
}

func (e *Engine) sshTarget(ctx context.Context, value string) (store.SSHTarget, error) {
	if e == nil || e.deps.Targets == nil {
		return store.SSHTarget{}, errors.New("target store is unavailable")
	}
	return e.deps.Targets.SSHTarget(ctx, value)
}

func sshPort(target store.SSHTarget) int {
	if target.SSHPort == 0 {
		return 22
	}
	return target.SSHPort
}

func sshTargetAvailable(target store.SSHTarget) bool {
	return target.Enabled
}

func (e *Engine) databaseTarget(ctx context.Context, value string) (store.DatabaseInstance, string, error) {
	instance, targetID, err := e.lookupDatabaseTarget(ctx, value)
	if err != nil {
		if err := e.openTUIForUnregisteredTarget(err); err != nil {
			return store.DatabaseInstance{}, "", err
		}
		return store.DatabaseInstance{}, "", err
	}
	return instance, targetID, nil
}

func (e *Engine) lookupDatabaseTarget(ctx context.Context, value string) (store.DatabaseInstance, string, error) {
	if e == nil || e.deps.Targets == nil {
		return store.DatabaseInstance{}, "", errors.New("target store is unavailable")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return store.DatabaseInstance{}, "", fmt.Errorf("invalid database target: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return store.DatabaseInstance{}, "", fmt.Errorf("invalid database target port: %w", err)
	}
	instance, err := e.deps.Targets.DatabaseInstance(ctx, host, port)
	if err != nil {
		return store.DatabaseInstance{}, "", err
	}
	return instance, net.JoinHostPort(instance.Host, strconv.Itoa(instance.Port)), nil
}

func (e *Engine) openTUIForUnregisteredTarget(targetErr error) error {
	if !errors.Is(targetErr, store.ErrTargetNotFound) {
		return nil
	}
	_ = e.openTUI()
	return nil
}

func (e *Engine) audit(ctx context.Context, requestID, targetKind, targetID, payload, decision, security string, exitStatus *int, affectedRows *int64, duration *int64, summary string) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	sshCommand, sqlStatement := auditOperation(payload)
	phase := auditlog.PhaseDecision
	remoteExecuted := duration != nil || exitStatus != nil || affectedRows != nil
	status := decision
	if summary == StatusOutcomeUnknown {
		phase = auditlog.PhaseFailed
		status = StatusOutcomeUnknown
	} else if summary == StatusNotDispatched || strings.HasPrefix(summary, "failure_kind=") {
		status = StatusNotDispatched
	} else if remoteExecuted {
		phase = auditlog.PhaseCompleted
		status = StatusCompleted
	}
	return e.deps.Audit.Record(ctx, auditlog.Event{
		Time:           clock.InBeijing(e.deps.Now()),
		OperationID:    requestID,
		Phase:          phase,
		RemoteExecuted: remoteExecuted,
		Action:         auditAction(targetKind, sshCommand, sqlStatement, payload),
		Actor:          e.deps.AuditActor,
		Target:         auditlog.Target{Kind: targetKind, ID: targetID},
		Policy:         auditlog.Policy{Version: policy.Version, Decision: decision},
		SSHCommand:     sshCommand,
		SQL:            sqlStatement,
		Result: auditlog.Result{
			Status: status, ExitStatus: exitStatus, AffectedRows: affectedRows, DurationMS: duration,
			Summary: summary, TransportSecurity: security,
		},
	})
}

func (e *Engine) auditStoppedBeforeDispatch(ctx context.Context, requestID, targetKind, targetID, payload string, decision policy.Decision) error {
	return e.auditTerminal(ctx, requestID, targetKind, targetID, payload, string(decision), "", nil, nil, nil, StatusNotDispatched)
}

func (e *Engine) auditTerminal(ctx context.Context, requestID, targetKind, targetID, payload, decision, security string, exitStatus *int, affectedRows *int64, duration *int64, summary string) error {
	auditContext, cancel := terminalAuditContext(ctx)
	defer cancel()
	return e.audit(auditContext, requestID, targetKind, targetID, payload, decision, security, exitStatus, affectedRows, duration, summary)
}

func (e *Engine) auditFinalTerminal(ctx context.Context, requestID, targetKind, targetID, payload string, decision policy.Result, phase string, result auditlog.Result) error {
	auditContext, cancel := terminalAuditContext(ctx)
	defer cancel()
	return e.auditFinal(auditContext, requestID, targetKind, targetID, payload, decision, phase, result)
}

func terminalAuditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), terminalAuditTimeout)
}

func remoteExecutionStarted(err error) bool {
	return !errors.Is(err, store.ErrTargetChanged) && !errors.Is(err, store.ErrTargetNotFound) &&
		!errors.Is(err, store.ErrLocked) && !errors.Is(err, store.ErrCredentialNotFound) &&
		!errors.Is(err, store.ErrWriteCredentialNotConfigured) &&
		!errors.Is(err, store.ErrHostKeyNotFound) && !errors.Is(err, store.ErrHostKeyMismatch) &&
		!errors.Is(err, store.ErrInvalidTarget) && !errors.Is(err, sshtransport.ErrNotDispatched) &&
		!errors.Is(err, sshtransport.ErrHostKeyMismatch) && !errors.Is(err, sshtransport.ErrInvalidEndpoint) &&
		!errors.Is(err, sshtransport.ErrInvalidCommand) && !errors.Is(err, dbtransport.ErrInvalidEndpoint) &&
		!errors.Is(err, dbtransport.ErrInvalidLimits) && !errors.Is(err, dbtransport.ErrInvalidStatements)
}

func (e *Engine) auditStarted(ctx context.Context, requestID, targetKind, targetID, sshCommand, sqlStatement, payload string, decision policy.Result) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	return e.deps.Audit.Record(ctx, auditlog.Event{
		Time:           clock.InBeijing(e.deps.Now()),
		OperationID:    requestID,
		Phase:          auditlog.PhaseStarted,
		RemoteExecuted: false,
		Action:         auditAction(targetKind, sshCommand, sqlStatement, payload),
		Actor:          e.deps.AuditActor,
		Target:         auditlog.Target{Kind: targetKind, ID: targetID},
		Policy:         auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Risk: string(decision.Risk), Reason: string(decision.Reason)},
		SSHCommand:     sshCommand,
		SQL:            sqlStatement,
		Result:         auditlog.Result{Status: "started"},
	})
}

func (e *Engine) auditFinal(ctx context.Context, requestID, targetKind, targetID, payload string, decision policy.Result, phase string, result auditlog.Result) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	sshCommand, sqlStatement := auditOperation(payload)
	return e.deps.Audit.Record(ctx, auditlog.Event{
		Time:           clock.InBeijing(e.deps.Now()),
		OperationID:    requestID,
		Phase:          phase,
		RemoteExecuted: true,
		Action:         auditAction(targetKind, sshCommand, sqlStatement, payload),
		Actor:          e.deps.AuditActor,
		Target:         auditlog.Target{Kind: targetKind, ID: targetID},
		Policy:         auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Risk: string(decision.Risk), Reason: string(decision.Reason)},
		SSHCommand:     sshCommand,
		SQL:            sqlStatement,
		Result:         result,
	})
}

func (e *Engine) auditDecision(ctx context.Context, requestID, targetKind, targetID, payload string, decision policy.Result, status string) error {
	if e == nil || e.deps.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	sshCommand, sqlStatement := auditOperation(payload)
	return e.deps.Audit.Record(ctx, auditlog.Event{
		Time:        clock.InBeijing(e.deps.Now()),
		OperationID: requestID,
		Phase:       auditlog.PhaseDecision,
		Action:      auditAction(targetKind, sshCommand, sqlStatement, payload),
		Actor:       e.deps.AuditActor,
		Target:      auditlog.Target{Kind: targetKind, ID: targetID},
		Policy:      auditlog.Policy{Version: policy.Version, Decision: string(decision.Decision), Risk: string(decision.Risk), Reason: string(decision.Reason)},
		SSHCommand:  sshCommand,
		SQL:         sqlStatement,
		Result:      auditlog.Result{Status: status},
	})
}

func auditWriteFailureResult(decision policy.Result, payload string, remoteExecuted bool) Result {
	return Result{
		Status:           StatusAuditWriteFailed,
		ExecutionOutcome: executionOutcomeForAuditFailure(remoteExecuted),
		AuditOutcome:     AuditOutcomeFailed,
		Message:          ResultMessage(StatusAuditWriteFailed, "", decision.Decision, decision.Reason),
		Decision:         decision.Decision,
		Reason:           decision.Reason,
		Risk:             decision.Risk,
		Payload:          payload,
		RemoteExecuted:   remoteExecuted,
		AuditWriteFailed: true,
	}
}

// ResultMessage provides a Chinese explanation without replacing stable
// machine-readable status, decision, reason, and failure_kind fields.
func ResultMessage(status, failureKind string, decision policy.Decision, reason policy.Reason) string {
	_ = decision
	if status == StatusCompleted {
		return ""
	}
	switch failureKind {
	case FailureKindWriteCredential:
		return "未配置可写账号，无法执行变更 SQL。请在本地控制台填写可写账号；若与只读账号相同，可留空可写密码并复用只读凭据。"
	case dbtransport.FailureKindSyntax:
		return "SQL 语法错误，数据库未完成该操作。"
	case dbtransport.FailureKindPermission:
		return "数据库账号权限不足，数据库未完成该操作。"
	case dbtransport.FailureKindConstraint:
		return "数据库约束拒绝了该操作。"
	}

	switch reason {
	case policy.ReasonUnlockRequired:
		return "本地凭据库已锁定，请先在本地控制台解锁。"
	case policy.ReasonTargetUnavailable:
		return "目标不可用、未登记或已停用，未派发远端操作。"
	case policy.ReasonInvalidRequest:
		return "请求格式无效，未派发远端操作。"
	}

	switch status {
	case StatusNotDispatched:
		return "操作在远端派发前停止，未执行。"
	case StatusOutcomeUnknown:
		return "远端操作可能已开始，但结果无法确认。请先根据任务风险执行新的核验或明确重试请求；SSH MCP 不会自动重放。"
	case StatusFailed:
		return "远端已明确返回失败，未完成请求的操作。请根据 failure_kind 或数据库错误修正后重试。"
	case StatusRejected:
		return "请求被硬拦截规则或必要前置条件拒绝，未派发远端操作。请查看 rule_id、命中内容和中文说明。"
	case StatusInteractiveInputRequired:
		return "该命令需要交互式终端输入，SSH MCP 的非交互协议不能派发。请由人工在终端执行。"
	case StatusUnlockRequired:
		return "本地凭据库已锁定，请先在本地控制台解锁。"
	case StatusTargetNotFound, StatusDatabaseNotFound:
		return "目标尚未登记，未派发远端操作。请在本地控制台新增并验证该目标。"
	case StatusAuditWriteFailed:
		return "本地审计写入失败；请查看 execution_outcome 确认远端操作结果。"
	}
	return "操作未完成，未派发远端操作。请检查状态、原因和目标连接配置。"
}

func sshSessionStatusResult(status string, decision policy.Result) SSHSessionResult {
	return SSHSessionResult{
		Status:   status,
		Message:  ResultMessage(status, "", decision.Decision, decision.Reason),
		Decision: decision.Decision,
		Reason:   decision.Reason,
	}
}

func executionOutcomeForStatus(status string) string {
	switch status {
	case StatusCompleted:
		return StatusCompleted
	case StatusFailed:
		return ExecutionOutcomeFailedKnown
	case StatusNotDispatched:
		return StatusNotDispatched
	case StatusOutcomeUnknown:
		return StatusOutcomeUnknown
	default:
		return ""
	}
}

func executionOutcomeForAuditFailure(remoteExecuted bool) string {
	if remoteExecuted {
		return StatusOutcomeUnknown
	}
	return StatusNotDispatched
}

func auditAction(targetKind, sshCommand, sqlStatement, payload string) string {
	if sshCommand != "" {
		return "ssh"
	}
	if sqlStatement != "" {
		return "sql"
	}
	if strings.Contains(payload, "kind=list_databases") {
		return "list_databases"
	}
	return targetKind
}

func auditOperation(payload string) (string, string) {
	if strings.HasPrefix(payload, "kind=ssh\ncommand=") {
		command := strings.TrimPrefix(payload, "kind=ssh\ncommand=")
		if end := strings.LastIndex(command, "\nas_root="); end >= 0 {
			command = command[:end]
		}
		return command, ""
	}
	if strings.HasPrefix(payload, "kind=sql\nengine=") {
		if start := strings.Index(payload, "\nstatement="); start >= 0 {
			statement := payload[start+len("\nstatement="):]
			if end := strings.LastIndex(statement, "\ntimeout="); end >= 0 {
				statement = statement[:end]
			}
			return "", statement
		}
	}
	return "", ""
}

func durationMS(start, end time.Time) *int64 {
	duration := end.Sub(start).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return &duration
}

func bindTarget(payload, targetKind, targetID string) string {
	return payload + "\ntarget_kind=" + targetKind + "\ntarget_id=" + targetID
}

// sqlStatementsForDispatch keeps parser normalization as an optimization, not
// an execution gate. A non-hard-blocked statement that the local parser does
// not understand is sent to the registered database as one raw statement so
// the server can return its authoritative syntax error.
func sqlStatementsForDispatch(engine store.DatabaseEngine, statement string) []string {
	if statements, err := policy.SplitStatements(engine, statement); err == nil && len(statements) > 0 {
		return statements
	}
	return []string{statement}
}

func sshOutputSummary(remote sshtransport.ExecutionResult) string {
	return fmt.Sprintf("SSH command completed: stdout_bytes=%d, stderr_bytes=%d, truncated=%t", len(remote.Stdout), len(remote.Stderr), remote.OutputTruncated)
}

func sqlOutputSummary(remote dbtransport.QueryResult) string {
	return fmt.Sprintf("query returned %d rows (%d columns), rows_truncated=%t, bytes_truncated=%t", len(remote.Rows), len(remote.Columns), remote.RowsTruncated, remote.BytesTruncated)
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func cloneRows(rows [][]string) [][]string {
	clone := make([][]string, len(rows))
	for index, row := range rows {
		clone[index] = append([]string(nil), row...)
	}
	return clone
}

var _ DatabaseService = (*dbservice.Service)(nil)
