// Package control defines the privileged local API used only by the spawned
// TUI. MCP tools never receive the IPC token and cannot invoke these methods.
package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/dbservice"
	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/secret"
	"ssh-mcp/internal/session"
	"ssh-mcp/internal/sshservice"
	"ssh-mcp/internal/store"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrConfirmationRequired      = errors.New("explicit confirmation is required")
	ErrCandidateAuditWriteFailed = errors.New("candidate validation audit write failed")
	ErrCandidateNotDispatched    = errors.New("candidate validation was not dispatched")
)

// DispatchLease 表示一次跨越全局远端派发边界的资格。
type DispatchLease interface {
	BeginDispatch() bool
	FinishDispatch()
}

// DispatchLeaseAcquirer 允许控制层复用执行层的全局派发栅栏而不依赖具体实现。
type DispatchLeaseAcquirer func() DispatchLease

type Service struct {
	store       *store.Store
	sessions    *session.Manager
	ssh         *sshservice.Service
	database    *dbservice.Service
	authorizers TargetAuthorizationRevoker
	auditor     auditlog.Recorder
	auditActor  auditlog.Actor
	dispatch    DispatchLeaseAcquirer

	// sshTargetMu 保证撤销、状态变更和激活作为一个有序事务完成。
	sshTargetMu sync.Locker
	// databaseTargetMu 保证数据库目标的撤销、状态变更和激活作为一个有序事务完成。
	databaseTargetMu sync.Locker
}

type Option func(*Service)

// TargetAuthorizationRevoker 在本地 TUI 变更登记目标后撤销易失的 MCP 授权。
type TargetAuthorizationRevoker interface {
	RevokeSSHTarget(string)
	RevokeDatabaseTarget(string)
}

// sshTargetActivator 在 SSH 目标完成变更后允许后续请求重新取得授权。
type sshTargetActivator interface {
	ActivateSSHTarget(string)
}

// databaseTargetActivator 在数据库目标完成变更后允许后续请求重新取得授权。
type databaseTargetActivator interface {
	ActivateDatabaseTarget(string)
}

func WithSSHTransport(transport sshservice.Transport) Option {
	return func(service *Service) {
		service.ssh = sshservice.New(service.store, transport)
	}
}

func WithDatabaseTransport(transport dbtransport.Transport) Option {
	return func(service *Service) {
		service.database = dbservice.New(service.store, transport)
	}
}

func WithTargetAuthorizationRevoker(revoker TargetAuthorizationRevoker) Option {
	return func(service *Service) {
		service.authorizers = revoker
	}
}

// WithAuditor 为候选目标连通性校验注入审计边界；省略时保持既有调用行为。
func WithAuditor(auditor auditlog.Recorder) Option {
	return func(service *Service) {
		service.auditor = auditor
	}
}

// WithAuditActor 设置由本地 TUI 触发的候选校验所使用的审计主体。
func WithAuditActor(actor auditlog.Actor) Option {
	return func(service *Service) {
		service.auditActor = actor
	}
}

// WithDispatchLeaseAcquirer 为候选目标验证接入全局远端派发栅栏。
// 省略时保持既有调用行为，便于独立使用控制服务。
func WithDispatchLeaseAcquirer(acquirer DispatchLeaseAcquirer) Option {
	return func(service *Service) {
		service.dispatch = acquirer
	}
}

func NewService(credentialStore *store.Store, sessions *session.Manager, options ...Option) *Service {
	service := &Service{
		store: credentialStore, sessions: sessions,
		ssh:              sshservice.New(credentialStore, sshservice.NativeTransport{}),
		database:         dbservice.New(credentialStore, dbtransport.NativeTransport{}),
		sshTargetMu:      &sync.Mutex{},
		databaseTargetMu: &sync.Mutex{},
	}
	for _, option := range options {
		option(service)
	}
	return service
}

// activateSSHTarget 仅通知支持激活回调的撤销器，保留已有撤销器实现的兼容性。
func (s *Service) activateSSHTarget(target string) {
	if activator, ok := s.authorizers.(sshTargetActivator); ok {
		activator.ActivateSSHTarget(target)
	}
}

// activateDatabaseTarget 仅通知支持激活回调的撤销器，保留已有撤销器实现的兼容性。
func (s *Service) activateDatabaseTarget(target string) {
	if activator, ok := s.authorizers.(databaseTargetActivator); ok {
		activator.ActivateDatabaseTarget(target)
	}
}

func (s *Service) validateSSHCandidate(ctx context.Context, vault *store.Vault, target store.SSHTarget, password []byte, confirmedFingerprint string) (sshservice.TestResult, error) {
	if err := store.ValidateSSHTargetConfiguration(target); err != nil {
		return sshservice.TestResult{}, err
	}
	targetID := strings.TrimSpace(target.IP)
	_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseStarted, "ssh", targetID, "started", "candidate_validation", "candidate_validation_started")
	lease, dispatched := s.beginCandidateDispatch()
	if !dispatched {
		_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseDecision, "ssh", targetID, "not_dispatched", "rejected", "dispatch_barrier_locked")
		return sshservice.TestResult{}, ErrCandidateNotDispatched
	}
	result, err := s.ssh.ValidateTargetConfiguration(ctx, vault, target, password, confirmedFingerprint)
	if lease != nil {
		lease.FinishDispatch()
	}
	if err != nil {
		_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseFailed, "ssh", targetID, "failed", "rejected", "candidate_validation_failed")
		return sshservice.TestResult{}, classifyCandidateValidationFailure(err)
	}
	if result.RequiresFingerprintConfirmation {
		_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseDecision, "ssh", targetID, "confirmation_required", "confirmation_required", "host_key_confirmation_required")
		return result, nil
	}
	_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseCompleted, "ssh", targetID, "completed", "allowed", "candidate_validation_verified")
	return result, nil
}

func (s *Service) validateDatabaseCandidate(ctx context.Context, vault *store.Vault, instance store.DatabaseInstance, candidates dbservice.CandidateCredentials) (dbservice.TestResult, error) {
	targetID := net.JoinHostPort(strings.TrimSpace(instance.Host), strconv.Itoa(instance.Port))
	_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseStarted, "database", targetID, "started", "candidate_validation", "candidate_validation_started")
	lease, dispatched := s.beginCandidateDispatch()
	if !dispatched {
		_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseDecision, "database", targetID, "not_dispatched", "rejected", "dispatch_barrier_locked")
		return dbservice.TestResult{}, ErrCandidateNotDispatched
	}
	result, err := s.database.ValidateInstanceConfiguration(ctx, vault, instance, candidates)
	if lease != nil {
		lease.FinishDispatch()
	}
	if err != nil {
		_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseFailed, "database", targetID, "failed", "rejected", "candidate_validation_failed")
		return dbservice.TestResult{}, classifyCandidateValidationFailure(err)
	}
	_ = s.recordCandidateValidationAudit(ctx, auditlog.PhaseCompleted, "database", targetID, "completed", "allowed", "candidate_validation_verified")
	return result, nil
}

// classifyCandidateValidationFailure exposes only a short local category over
// IPC. The original driver or remote error remains local and is never encoded
// in the response sent to the TUI.
func classifyCandidateValidationFailure(err error) error {
	if err == nil || errors.Is(err, store.ErrLocked) || errors.Is(err, ipc.ErrInvalidRequest) {
		return err
	}
	if isTLSCandidateValidationFailure(err) {
		return ipc.Categorize(err, ipc.ErrCandidateTLSFailed)
	}
	if isAuthenticationCandidateValidationFailure(err) {
		return ipc.Categorize(err, ipc.ErrCandidateAuthenticationFailed)
	}
	if isConnectionCandidateValidationFailure(err) {
		return ipc.Categorize(err, ipc.ErrCandidateConnectionFailed)
	}
	return err
}

func isTLSCandidateValidationFailure(err error) bool {
	var verificationError *tls.CertificateVerificationError
	var recordHeaderError tls.RecordHeaderError
	var unknownAuthorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &verificationError) ||
		errors.As(err, &recordHeaderError) ||
		errors.As(err, &unknownAuthorityError) ||
		errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalidError) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "mysql server did not negotiate required tls") ||
		strings.Contains(message, "postgresql server refused required tls") ||
		strings.Contains(message, "invalid postgresql tls response") ||
		strings.Contains(message, "read database ca certificate") ||
		strings.Contains(message, "parse database ca certificate")
}

func isAuthenticationCandidateValidationFailure(err error) bool {
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) {
		switch mysqlError.Number {
		case 1044, 1045, 1142, 1227:
			return true
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "28000", "28P01", "42501":
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unable to authenticate") ||
		strings.Contains(message, "authentication failed") ||
		strings.Contains(message, "permission denied")
}

func isConnectionCandidateValidationFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var connectionError *pgconn.ConnectError
	if errors.As(err, &connectionError) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func (s *Service) beginCandidateDispatch() (DispatchLease, bool) {
	if s == nil || s.dispatch == nil {
		return nil, true
	}
	lease := s.dispatch()
	if lease == nil || !lease.BeginDispatch() {
		return nil, false
	}
	return lease, true
}

func (s *Service) recordCandidateValidationAudit(ctx context.Context, phase, targetKind, targetID, status, decision, reason string) error {
	if s == nil || s.auditor == nil {
		return nil
	}
	err := s.auditor.Record(ctx, auditlog.Event{
		Phase:  phase,
		Action: "candidate_target_validation",
		Actor:  s.auditActor,
		Target: auditlog.Target{Kind: targetKind, ID: targetID},
		Policy: auditlog.Policy{Decision: decision, Reason: reason},
		Result: auditlog.Result{Status: status},
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCandidateAuditWriteFailed, err)
	}
	return nil
}

// prepareDatabaseInstanceConfiguration 只允许候选配置复用同一登记目标、同一身份的既有凭据。
func (s *Service) prepareDatabaseInstanceConfiguration(ctx context.Context, instance store.DatabaseInstance, readPassword, writePassword []byte) (store.DatabaseInstance, store.DatabaseInstance, bool, error) {
	existing, err := s.store.DatabaseInstance(ctx, instance.Host, instance.Port)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrTargetNotFound) {
		return store.DatabaseInstance{}, store.DatabaseInstance{}, false, err
	}

	configuration := instance
	configuration.ReadUsername = strings.TrimSpace(configuration.ReadUsername)
	configuration.WriteUsername = strings.TrimSpace(configuration.WriteUsername)
	// 凭据标识由目标专属归属决定，调用方提供的标识不得参与候选验证或落库。
	configuration.ReadCredentialID = ""
	configuration.WriteCredentialID = ""
	// 版本状态只能由候选验证写入，不能由本地控制请求伪造。
	configuration.MajorVersion = 0
	configuration.VersionStatus = store.DatabaseVersionUnverified
	if exists {
		configuration.Host = existing.Host
		configuration.Port = existing.Port
	}
	if len(readPassword) == 0 {
		if !exists || configuration.ReadUsername != existing.ReadUsername {
			return store.DatabaseInstance{}, store.DatabaseInstance{}, false, ipc.ErrInvalidRequest
		}
		configuration.ReadCredentialID = existing.ReadCredentialID
	}
	if configuration.WriteUsername == "" {
		if len(writePassword) != 0 {
			return store.DatabaseInstance{}, store.DatabaseInstance{}, false, ipc.ErrInvalidRequest
		}
	} else if configuration.WriteUsername == configuration.ReadUsername && len(writePassword) == 0 && (!exists || existing.WriteCredentialID == "") {
		// An explicitly configured same login reuses the read credential unless
		// the operator supplies a separate replacement write password.
		configuration.WriteCredentialID = ""
	} else if len(writePassword) == 0 {
		if !exists || existing.WriteCredentialID == "" || configuration.WriteUsername != existing.WriteUsername {
			return store.DatabaseInstance{}, store.DatabaseInstance{}, false, ipc.ErrInvalidRequest
		}
		configuration.WriteCredentialID = existing.WriteCredentialID
	}
	return configuration, existing, exists, nil
}

type Status struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
}

type UnlockParams struct {
	MasterPassword string `json:"master_password"`
}

type UnlockResult struct {
	Created  bool `json:"created"`
	Unlocked bool `json:"unlocked"`
}

type TargetsResult struct {
	SSH       []store.SSHTarget        `json:"ssh"`
	Databases []store.DatabaseInstance `json:"databases"`
}

type UpsertSSHTargetParams struct {
	Target               store.SSHTarget `json:"target"`
	Password             string          `json:"password"`
	ConfirmedFingerprint string          `json:"confirmed_fingerprint"`
}

type UpsertDatabaseInstanceParams struct {
	Instance      store.DatabaseInstance `json:"instance"`
	ReadPassword  string                 `json:"read_password"`
	WritePassword string                 `json:"write_password"`
}

type SetSSHTargetEnabledParams struct {
	IP      string `json:"ip"`
	Enabled bool   `json:"enabled"`
}

type SetDatabaseInstanceEnabledParams struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

type DeleteSSHTargetParams struct {
	IP string `json:"ip"`
}

type DeleteDatabaseInstanceParams struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type SSHTestParams struct {
	Target               store.SSHTarget `json:"target"`
	Password             string          `json:"password"`
	ConfirmedFingerprint string          `json:"confirmed_fingerprint"`
}

type SSHTestResult struct {
	Fingerprint                     string `json:"fingerprint"`
	RequiresFingerprintConfirmation bool   `json:"requires_fingerprint_confirmation"`
}

type DatabaseTestParams struct {
	Instance      store.DatabaseInstance `json:"instance"`
	ReadPassword  string                 `json:"read_password"`
	WritePassword string                 `json:"write_password"`
}

type DatabaseTestResult struct {
	TransportSecurity store.TransportSecurity     `json:"transport_security"`
	MajorVersion      int                         `json:"major_version"`
	VersionStatus     store.DatabaseVersionStatus `json:"version_status"`
}

type BackupCreateParams struct {
	MasterPassword string `json:"master_password"`
	Destination    string `json:"destination"`
}

type BackupRestoreParams struct {
	MasterPassword string `json:"master_password"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
}

type RotateDataKeyParams struct {
	MasterPassword string `json:"master_password"`
	Confirmation   string `json:"confirmation"`
}

type ChangeMasterPasswordParams struct {
	OldMasterPassword string `json:"old_master_password"`
	NewMasterPassword string `json:"new_master_password"`
}

func (s *Service) Handle(ctx context.Context, method string, params json.RawMessage) (result any, err error) {
	defer func() {
		err = classifyLocalControlError(err)
	}()
	switch method {
	case "status":
		return s.status(ctx)
	case "unlock":
		return s.unlock(ctx, params)
	case "lock":
		s.sessions.Lock()
		return struct{}{}, nil
	case "targets.list":
		return s.listTargets(ctx)
	case "target.upsert_ssh":
		return s.upsertSSHTarget(ctx, params)
	case "target.set_ssh_enabled":
		return s.setSSHTargetEnabled(ctx, params)
	case "target.delete_ssh":
		return s.deleteSSHTarget(ctx, params)
	case "target.upsert_database":
		return s.upsertDatabaseInstance(ctx, params)
	case "target.set_database_enabled":
		return s.setDatabaseInstanceEnabled(ctx, params)
	case "target.delete_database":
		return s.deleteDatabaseInstance(ctx, params)
	case "ssh.test_target":
		return s.testSSHTarget(ctx, params)
	case "database.test_target":
		return s.testDatabaseInstance(ctx, params)
	case "backup.create":
		return s.createBackup(ctx, params)
	case "backup.restore":
		return s.restoreBackup(ctx, params)
	case "keys.rotate":
		return s.rotateDataKey(ctx, params)
	case "keys.change_master_password":
		return s.changeMasterPassword(ctx, params)
	default:
		return nil, ipc.ErrMethodNotFound
	}
}

func classifyLocalControlError(err error) error {
	if err == nil ||
		errors.Is(err, ipc.ErrLocked) ||
		errors.Is(err, ipc.ErrCandidateNotDispatched) ||
		errors.Is(err, ipc.ErrCandidateAuditWriteFailed) ||
		errors.Is(err, ipc.ErrConfirmationRequired) ||
		errors.Is(err, ipc.ErrCandidateConnectionFailed) ||
		errors.Is(err, ipc.ErrCandidateAuthenticationFailed) ||
		errors.Is(err, ipc.ErrCandidateTLSFailed) {
		return err
	}
	switch {
	case errors.Is(err, store.ErrLocked):
		return ipc.Categorize(err, ipc.ErrLocked)
	case errors.Is(err, store.ErrInvalidTarget):
		return ipc.Categorize(err, ipc.ErrInvalidRequest)
	case errors.Is(err, ErrCandidateNotDispatched):
		return ipc.Categorize(err, ipc.ErrCandidateNotDispatched)
	case errors.Is(err, ErrCandidateAuditWriteFailed):
		return ipc.Categorize(err, ipc.ErrCandidateAuditWriteFailed)
	case errors.Is(err, ErrConfirmationRequired):
		return ipc.Categorize(err, ipc.ErrConfirmationRequired)
	default:
		return err
	}
}

func (s *Service) status(ctx context.Context) (Status, error) {
	initialized, err := s.store.IsInitialized(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{Initialized: initialized, Unlocked: s.sessions.IsUnlocked()}, nil
}

func (s *Service) unlock(ctx context.Context, params json.RawMessage) (UnlockResult, error) {
	input, err := decodeParams[UnlockParams](params)
	if err != nil || strings.TrimSpace(input.MasterPassword) == "" {
		return UnlockResult{}, ipc.ErrInvalidRequest
	}
	password := []byte(input.MasterPassword)
	defer secret.Zero(password)
	created, err := s.sessions.Unlock(ctx, password)
	if err != nil {
		return UnlockResult{}, err
	}
	return UnlockResult{Created: created, Unlocked: true}, nil
}

func (s *Service) listTargets(ctx context.Context) (TargetsResult, error) {
	sshTargets, err := s.store.ListSSHTargets(ctx)
	if err != nil {
		return TargetsResult{}, err
	}
	databases, err := s.store.ListDatabaseInstances(ctx)
	if err != nil {
		return TargetsResult{}, err
	}
	return TargetsResult{SSH: sshTargets, Databases: databases}, nil
}

func (s *Service) upsertSSHTarget(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.sshTargetMu.Lock()
	defer s.sshTargetMu.Unlock()

	input, allowFileOperationsSet, err := decodeUpsertSSHTargetParams(params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	existing, existingErr := s.store.SSHTarget(ctx, input.Target.IP)
	if existingErr != nil && !errors.Is(existingErr, store.ErrTargetNotFound) {
		return struct{}{}, existingErr
	}
	// Requests from older local clients do not contain the capability field.
	// Preserve an existing choice and use the permissive default for a new
	// target; an explicitly supplied false remains authoritative.
	if !allowFileOperationsSet {
		if existingErr == nil {
			input.Target.AllowFileOperations = existing.AllowFileOperations
		} else {
			input.Target.AllowFileOperations = true
		}
	}
	vault, err := s.sessions.Vault()
	if err != nil {
		return struct{}{}, err
	}
	if input.Password == "" && existingErr != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	affectedTarget := ""
	if existingErr == nil {
		affectedTarget = existing.IP
	}
	completed := false
	if s.authorizers != nil && affectedTarget != "" {
		s.authorizers.RevokeSSHTarget(affectedTarget)
		defer func() {
			if !completed {
				s.activateSSHTarget(affectedTarget)
			}
		}()
	}
	password := []byte(input.Password)
	defer secret.Zero(password)
	if input.Password == "" {
		input.Target.CredentialID = existing.CredentialID
	}
	validated, err := s.validateSSHCandidate(ctx, vault, input.Target, password, input.ConfirmedFingerprint)
	if err != nil {
		return struct{}{}, err
	}
	if validated.RequiresFingerprintConfirmation {
		return struct{}{}, ErrConfirmationRequired
	}
	saved, err := vault.CommitValidatedSSHTargetConfiguration(ctx, store.ValidatedSSHTargetConfiguration{
		Target: input.Target, Password: password, ConfirmedFingerprint: validated.Fingerprint,
	})
	if err != nil {
		return struct{}{}, err
	}
	s.activateSSHTarget(saved.IP)
	completed = true
	return struct{}{}, nil
}

func (s *Service) setSSHTargetEnabled(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.sshTargetMu.Lock()
	defer s.sshTargetMu.Unlock()

	input, err := decodeParams[SetSSHTargetEnabledParams](params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	if _, err := s.sessions.Vault(); err != nil {
		return struct{}{}, err
	}
	target, err := s.store.SSHTarget(ctx, input.IP)
	if err != nil {
		return struct{}{}, err
	}
	completed := false
	if s.authorizers != nil {
		s.authorizers.RevokeSSHTarget(target.IP)
		defer func() {
			if !completed {
				s.activateSSHTarget(target.IP)
			}
		}()
	}
	if err := s.store.SetSSHTargetEnabled(ctx, input.IP, input.Enabled); err != nil {
		return struct{}{}, err
	}
	if input.Enabled {
		s.activateSSHTarget(target.IP)
	}
	completed = true
	return struct{}{}, nil
}

func (s *Service) deleteSSHTarget(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.sshTargetMu.Lock()
	defer s.sshTargetMu.Unlock()

	input, err := decodeParams[DeleteSSHTargetParams](params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	if _, err := s.sessions.Vault(); err != nil {
		return struct{}{}, err
	}
	target, err := s.store.SSHTarget(ctx, input.IP)
	if err != nil {
		return struct{}{}, err
	}
	deleted := false
	if s.authorizers != nil {
		s.authorizers.RevokeSSHTarget(target.IP)
		defer func() {
			if !deleted {
				s.activateSSHTarget(target.IP)
			}
		}()
	}
	if err := s.store.DeleteSSHTarget(ctx, target.IP); err != nil {
		return struct{}{}, err
	}
	deleted = true
	return struct{}{}, nil
}

func (s *Service) upsertDatabaseInstance(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.databaseTargetMu.Lock()
	defer s.databaseTargetMu.Unlock()

	input, err := decodeParams[UpsertDatabaseInstanceParams](params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	readPassword := []byte(input.ReadPassword)
	writePassword := []byte(input.WritePassword)
	defer secret.Zero(readPassword)
	defer secret.Zero(writePassword)
	configuration, existing, exists, err := s.prepareDatabaseInstanceConfiguration(ctx, input.Instance, readPassword, writePassword)
	if err != nil {
		return struct{}{}, err
	}
	vault, err := s.sessions.Vault()
	if err != nil {
		return struct{}{}, err
	}

	affectedTarget := ""
	if exists {
		affectedTarget = net.JoinHostPort(existing.Host, strconv.Itoa(existing.Port))
	}
	completed := false
	if s.authorizers != nil && affectedTarget != "" {
		s.authorizers.RevokeDatabaseTarget(affectedTarget)
		defer func() {
			if !completed && existing.Enabled {
				s.activateDatabaseTarget(affectedTarget)
			}
		}()
	}

	validated, err := s.validateDatabaseCandidate(ctx, vault, configuration, dbservice.CandidateCredentials{
		ReadPassword: readPassword, WritePassword: writePassword,
	})
	if err != nil {
		return struct{}{}, err
	}
	configuration.TransportSecurity = validated.TransportSecurity
	configuration.MajorVersion = validated.MajorVersion
	configuration.VersionStatus = validated.VersionStatus
	saved, err := vault.CommitValidatedDatabaseInstanceConfiguration(ctx, store.ValidatedDatabaseInstanceConfiguration{
		Instance: configuration, ReadPassword: readPassword, WritePassword: writePassword,
	})
	if err != nil {
		return struct{}{}, err
	}
	if saved.Enabled {
		s.activateDatabaseTarget(net.JoinHostPort(saved.Host, strconv.Itoa(saved.Port)))
	}
	completed = true
	return struct{}{}, nil
}

func (s *Service) setDatabaseInstanceEnabled(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.databaseTargetMu.Lock()
	defer s.databaseTargetMu.Unlock()

	input, err := decodeParams[SetDatabaseInstanceEnabledParams](params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	if _, err := s.sessions.Vault(); err != nil {
		return struct{}{}, err
	}
	instance, err := s.store.DatabaseInstance(ctx, input.Host, input.Port)
	if err != nil {
		return struct{}{}, err
	}
	target := net.JoinHostPort(instance.Host, strconv.Itoa(instance.Port))
	completed := false
	if s.authorizers != nil {
		s.authorizers.RevokeDatabaseTarget(target)
		defer func() {
			if !completed && instance.Enabled {
				s.activateDatabaseTarget(target)
			}
		}()
	}
	if err := s.store.SetDatabaseInstanceEnabled(ctx, input.Host, input.Port, input.Enabled); err != nil {
		return struct{}{}, err
	}
	if input.Enabled {
		s.activateDatabaseTarget(target)
	}
	completed = true
	return struct{}{}, nil
}

func (s *Service) deleteDatabaseInstance(ctx context.Context, params json.RawMessage) (struct{}, error) {
	s.databaseTargetMu.Lock()
	defer s.databaseTargetMu.Unlock()

	input, err := decodeParams[DeleteDatabaseInstanceParams](params)
	if err != nil {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	if _, err := s.sessions.Vault(); err != nil {
		return struct{}{}, err
	}
	instance, err := s.store.DatabaseInstance(ctx, input.Host, input.Port)
	if err != nil {
		return struct{}{}, err
	}
	target := net.JoinHostPort(instance.Host, strconv.Itoa(instance.Port))
	deleted := false
	if s.authorizers != nil {
		s.authorizers.RevokeDatabaseTarget(target)
		defer func() {
			if !deleted && instance.Enabled {
				s.activateDatabaseTarget(target)
			}
		}()
	}
	if err := s.store.DeleteDatabaseInstance(ctx, instance.Host, instance.Port); err != nil {
		return struct{}{}, err
	}
	deleted = true
	return struct{}{}, nil
}

func (s *Service) testSSHTarget(ctx context.Context, params json.RawMessage) (SSHTestResult, error) {
	input, err := decodeParams[SSHTestParams](params)
	if err != nil {
		return SSHTestResult{}, ipc.ErrInvalidRequest
	}
	vault, err := s.sessions.Vault()
	if err != nil {
		return SSHTestResult{}, err
	}
	password := []byte(input.Password)
	defer secret.Zero(password)
	result, err := s.validateSSHCandidate(ctx, vault, input.Target, password, input.ConfirmedFingerprint)
	if err != nil {
		return SSHTestResult{}, err
	}
	return SSHTestResult{Fingerprint: result.Fingerprint, RequiresFingerprintConfirmation: result.RequiresFingerprintConfirmation}, nil
}

func (s *Service) testDatabaseInstance(ctx context.Context, params json.RawMessage) (DatabaseTestResult, error) {
	s.databaseTargetMu.Lock()
	defer s.databaseTargetMu.Unlock()

	input, err := decodeParams[DatabaseTestParams](params)
	if err != nil {
		return DatabaseTestResult{}, ipc.ErrInvalidRequest
	}
	vault, err := s.sessions.Vault()
	if err != nil {
		return DatabaseTestResult{}, err
	}
	readPassword := []byte(input.ReadPassword)
	writePassword := []byte(input.WritePassword)
	defer secret.Zero(readPassword)
	defer secret.Zero(writePassword)
	configuration, _, _, err := s.prepareDatabaseInstanceConfiguration(ctx, input.Instance, readPassword, writePassword)
	if err != nil {
		return DatabaseTestResult{}, err
	}
	result, err := s.validateDatabaseCandidate(ctx, vault, configuration, dbservice.CandidateCredentials{
		ReadPassword: readPassword, WritePassword: writePassword,
	})
	if err != nil {
		return DatabaseTestResult{}, err
	}
	return DatabaseTestResult{
		TransportSecurity: result.TransportSecurity,
		MajorVersion:      result.MajorVersion,
		VersionStatus:     result.VersionStatus,
	}, nil
}

func (s *Service) createBackup(ctx context.Context, params json.RawMessage) (struct{}, error) {
	input, err := decodeParams[BackupCreateParams](params)
	if err != nil || strings.TrimSpace(input.MasterPassword) == "" || strings.TrimSpace(input.Destination) == "" {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	password := []byte(input.MasterPassword)
	defer secret.Zero(password)
	return struct{}{}, s.store.CreateBackup(ctx, password, input.Destination)
}

func (s *Service) restoreBackup(ctx context.Context, params json.RawMessage) (struct{}, error) {
	input, err := decodeParams[BackupRestoreParams](params)
	if err != nil || strings.TrimSpace(input.MasterPassword) == "" || strings.TrimSpace(input.Source) == "" || strings.TrimSpace(input.Destination) == "" {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	password := []byte(input.MasterPassword)
	defer secret.Zero(password)
	return struct{}{}, store.RestoreBackup(ctx, password, input.Source, input.Destination)
}

func (s *Service) rotateDataKey(ctx context.Context, params json.RawMessage) (struct{}, error) {
	input, err := decodeParams[RotateDataKeyParams](params)
	if err != nil || strings.TrimSpace(input.MasterPassword) == "" {
		return struct{}{}, ipc.ErrInvalidRequest
	}
	if input.Confirmation != "ROTATE" {
		return struct{}{}, ErrConfirmationRequired
	}
	password := []byte(input.MasterPassword)
	defer secret.Zero(password)
	return struct{}{}, s.store.RotateDataKey(ctx, password)
}

func (s *Service) changeMasterPassword(ctx context.Context, params json.RawMessage) (struct{}, error) {
	var input ChangeMasterPasswordParams
	if err := json.Unmarshal(params, &input); err != nil || strings.TrimSpace(input.OldMasterPassword) == "" || strings.TrimSpace(input.NewMasterPassword) == "" {
		return struct{}{}, store.ErrInvalidTarget
	}
	oldPassword := []byte(input.OldMasterPassword)
	newPassword := []byte(input.NewMasterPassword)
	defer secret.Zero(oldPassword)
	defer secret.Zero(newPassword)
	return struct{}{}, s.store.ChangeMasterPassword(ctx, oldPassword, newPassword)
}

func decodeParams[T any](params json.RawMessage) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if decoder.More() {
		return value, errors.New("unexpected additional JSON value")
	}
	return value, nil
}

func decodeUpsertSSHTargetParams(params json.RawMessage) (UpsertSSHTargetParams, bool, error) {
	input, err := decodeParams[UpsertSSHTargetParams](params)
	if err != nil {
		return input, false, err
	}
	var envelope struct {
		Target map[string]json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return input, false, err
	}
	for name := range envelope.Target {
		compact := strings.ReplaceAll(strings.ToLower(name), "_", "")
		if compact == "allowfileoperations" {
			return input, true, nil
		}
	}
	return input, false, nil
}

var _ ipc.Handler = (*Service)(nil)

func (s *Service) Close() {
	s.sessions.Close()
}
