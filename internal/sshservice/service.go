// Package sshservice resolves registered SSH targets into pinned,
// non-interactive transport endpoints.
package sshservice

import (
	"context"
	"errors"
	"io"
	"strings"

	"ssh-mcp/internal/secret"
	"ssh-mcp/internal/sshtransport"
	"ssh-mcp/internal/store"
)

type Transport interface {
	ProbeHostKey(context.Context, sshtransport.Endpoint) (string, error)
	TestCommand(context.Context, sshtransport.Endpoint) error
}

type Executor interface {
	Execute(context.Context, sshtransport.Endpoint, string, bool, int) (sshtransport.ExecutionResult, error)
}

// FileReader is the runner-facing constrained file inspection boundary. It
// deliberately has no write, directory, glob, or shell operation.
type FileReader interface {
	ReadFile(context.Context, *store.Vault, store.SSHTarget, string, int64, int) (sshtransport.FileReadResult, error)
}

// BinaryDeployer is the runner-facing controlled deployment boundary. It has
// no arbitrary local path, backup name, or command parameter.
type BinaryDeployer interface {
	DeployBinary(context.Context, *store.Vault, store.SSHTarget, io.Reader, sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error)
}

var errBinaryDeploymentUnavailable = errors.New("isolated SSH connection does not support controlled binary deployment")

type Service struct {
	store     *store.Store
	transport Transport
	executor  Executor
	isolated  *isolatedConnectionPool
}

const controlledBinaryDeploymentSpecificationVersion = "controlled-binary-deployment-v1"

type TestResult struct {
	Fingerprint                     string
	RequiresFingerprintConfirmation bool
}

func New(credentialStore *store.Store, transport Transport, executors ...Executor) *Service {
	return NewWithIsolatedDialer(credentialStore, transport, nativeIsolatedDialer{}, executors...)
}

// NewWithIsolatedDialer 为隔离执行提供可替换的物理连接建立器。
func NewWithIsolatedDialer(credentialStore *store.Store, transport Transport, dialer IsolatedDialer, executors ...Executor) *Service {
	executor := Executor(NativeExecutor{})
	if len(executors) > 0 && executors[0] != nil {
		executor = executors[0]
	}
	return &Service{store: credentialStore, transport: transport, executor: executor, isolated: newIsolatedConnectionPool(dialer)}
}

func (s *Service) TestTarget(ctx context.Context, vault *store.Vault, target store.SSHTarget, directPassword []byte, confirmedFingerprint string) (TestResult, error) {
	return s.ValidateTargetConfiguration(ctx, vault, target, directPassword, confirmedFingerprint)
}

// ValidateTargetConfiguration 在提交本地配置变更前重新验证已确认的 SSH 配置变更。
// 传入的指纹必须与本次验证观察到的指纹相等，且该方法绝不持久化主机身份。
func (s *Service) ValidateTargetConfiguration(ctx context.Context, vault *store.Vault, target store.SSHTarget, directPassword []byte, confirmedFingerprint string) (TestResult, error) {
	endpoint, err := s.configurationEndpoint(ctx, vault, target, directPassword)
	if err != nil {
		return TestResult{}, err
	}
	defer secret.Zero(endpoint.Password)
	return s.validateConfigurationEndpoint(ctx, endpoint, confirmedFingerprint)
}

func (s *Service) validateConfigurationEndpoint(ctx context.Context, endpoint sshtransport.Endpoint, confirmedFingerprint string) (TestResult, error) {
	pinnedFingerprint, err := s.store.HostKeyFingerprint(ctx, endpoint.Host, endpoint.Port)
	if errors.Is(err, store.ErrHostKeyNotFound) {
		return s.confirmOrRequestConfigurationFingerprint(ctx, endpoint, confirmedFingerprint)
	}
	if err != nil {
		return TestResult{}, err
	}
	endpoint.Fingerprint = pinnedFingerprint
	if err := s.transport.TestCommand(ctx, endpoint); errors.Is(err, sshtransport.ErrHostKeyMismatch) {
		return s.confirmOrRequestConfigurationFingerprint(ctx, endpoint, confirmedFingerprint)
	} else if err != nil {
		return TestResult{}, err
	}
	return TestResult{Fingerprint: pinnedFingerprint}, nil
}

func (s *Service) confirmOrRequestConfigurationFingerprint(ctx context.Context, endpoint sshtransport.Endpoint, confirmedFingerprint string) (TestResult, error) {
	fingerprint, err := s.transport.ProbeHostKey(ctx, endpoint)
	if err != nil {
		return TestResult{}, err
	}
	if confirmedFingerprint != fingerprint {
		return TestResult{Fingerprint: fingerprint, RequiresFingerprintConfirmation: true}, nil
	}
	endpoint.Fingerprint = fingerprint
	if err := s.transport.TestCommand(ctx, endpoint); err != nil {
		return TestResult{}, err
	}
	return TestResult{Fingerprint: fingerprint}, nil
}

func (s *Service) configurationEndpoint(ctx context.Context, vault *store.Vault, target store.SSHTarget, directPassword []byte) (sshtransport.Endpoint, error) {
	if target.SSHPort == 0 {
		target.SSHPort = 22
	}
	target.Enabled = true
	return s.endpoint(ctx, vault, target, directPassword)
}

func (s *Service) endpoint(ctx context.Context, vault *store.Vault, target store.SSHTarget, directPassword []byte) (sshtransport.Endpoint, error) {
	if !target.Enabled {
		return sshtransport.Endpoint{}, store.ErrTargetNotFound
	}
	if target.Mode != store.SSHDirect {
		return sshtransport.Endpoint{}, store.ErrInvalidTarget
	}
	if len(directPassword) == 0 {
		password, err := vault.Credential(ctx, target.CredentialID)
		if err != nil {
			return sshtransport.Endpoint{}, err
		}
		return sshtransport.Endpoint{Host: target.IP, Port: target.SSHPort, Username: target.LoginUsername, Password: password}, nil
	}
	return sshtransport.Endpoint{Host: target.IP, Port: target.SSHPort, Username: target.LoginUsername, Password: append([]byte(nil), directPassword...)}, nil
}

func (s *Service) Execute(ctx context.Context, vault *store.Vault, target store.SSHTarget, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	if s == nil || s.executor == nil {
		return sshtransport.ExecutionResult{}, store.ErrInvalidTarget
	}
	_, endpoint, err := s.executionEndpoint(ctx, vault, target)
	if err != nil {
		return sshtransport.ExecutionResult{}, err
	}
	defer secret.Zero(endpoint.Password)
	return s.executor.Execute(ctx, endpoint, command, asRoot, maxBytes)
}

// ExecuteIsolated 在不继承工作会话状态的前提下复用已认证物理连接。
func (s *Service) ExecuteIsolated(ctx context.Context, vault *store.Vault, target store.SSHTarget, specificationVersion, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	if s == nil || s.isolated == nil || strings.TrimSpace(specificationVersion) == "" {
		return sshtransport.ExecutionResult{}, store.ErrInvalidTarget
	}
	if err := ctx.Err(); err != nil {
		return sshtransport.ExecutionResult{}, notDispatched(err)
	}
	lease, err := s.isolated.AcquireTarget(target.IP)
	if err != nil {
		return sshtransport.ExecutionResult{}, err
	}
	current, endpoint, err := s.executionEndpoint(ctx, vault, target)
	if err != nil {
		return sshtransport.ExecutionResult{}, notDispatched(err)
	}
	defer secret.Zero(endpoint.Password)
	key := isolatedConnectionKey{
		Target: current.IP, TargetRevision: current.Revision, Port: current.SSHPort,
		Username: current.LoginUsername, CredentialID: current.CredentialID,
		Fingerprint: endpoint.Fingerprint, SpecificationVersion: specificationVersion,
	}
	return lease.Execute(ctx, key, endpoint, command, asRoot, maxBytes)
}

// ReadFile reads one bounded remote regular file through the daemon-held,
// host-key-pinned SSH connection. It uses the isolated target gate so target
// revisions, configuration revocation, lock and shutdown cancel or reject it
// exactly like other remote dispatches.
func (s *Service) ReadFile(ctx context.Context, vault *store.Vault, target store.SSHTarget, remotePath string, offset int64, maxBytes int) (sshtransport.FileReadResult, error) {
	if s == nil || s.isolated == nil {
		return sshtransport.FileReadResult{}, store.ErrInvalidTarget
	}
	if err := ctx.Err(); err != nil {
		return sshtransport.FileReadResult{}, notDispatched(err)
	}
	lease, err := s.isolated.AcquireTarget(target.IP)
	if err != nil {
		return sshtransport.FileReadResult{}, err
	}
	current, endpoint, err := s.executionEndpoint(ctx, vault, target)
	if err != nil {
		return sshtransport.FileReadResult{}, notDispatched(err)
	}
	defer secret.Zero(endpoint.Password)
	key := isolatedConnectionKey{
		Target: current.IP, TargetRevision: current.Revision, Port: current.SSHPort,
		Username: current.LoginUsername, CredentialID: current.CredentialID,
		Fingerprint: endpoint.Fingerprint, SpecificationVersion: "constrained-file-read-v1",
	}
	return lease.ReadFile(ctx, key, endpoint, remotePath, offset, maxBytes)
}

// DeployBinary dispatches one controlled binary transaction through the
// daemon-held, host-key-pinned SSH connection. The target lease and current
// execution revision are captured before the transport can write remotely;
// no generic command or SFTP writer is exposed to callers.
func (s *Service) DeployBinary(ctx context.Context, vault *store.Vault, target store.SSHTarget, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	if s == nil || s.isolated == nil {
		return sshtransport.BinaryDeploymentResult{}, store.ErrInvalidTarget
	}
	if err := ctx.Err(); err != nil {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(err)
	}
	lease, err := s.isolated.AcquireTarget(target.IP)
	if err != nil {
		return sshtransport.BinaryDeploymentResult{}, err
	}
	current, endpoint, err := s.executionEndpoint(ctx, vault, target)
	if err != nil {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(err)
	}
	defer secret.Zero(endpoint.Password)
	key := isolatedConnectionKey{
		Target: current.IP, TargetRevision: current.Revision, Port: current.SSHPort,
		Username: current.LoginUsername, CredentialID: current.CredentialID,
		Fingerprint: endpoint.Fingerprint, SpecificationVersion: controlledBinaryDeploymentSpecificationVersion,
	}
	return lease.DeployBinary(ctx, key, endpoint, source, request)
}

// InvalidateTarget 阻断目标的旧执行快照，直到配置更新完成后显式激活。
func (s *Service) InvalidateTarget(target string) {
	if s != nil && s.isolated != nil {
		s.isolated.InvalidateTarget(target)
	}
}

// ActivateTarget 在目标配置成功持久化后允许新的隔离诊断。
func (s *Service) ActivateTarget(target string) {
	if s != nil && s.isolated != nil {
		s.isolated.ActivateTarget(target)
	}
}

// CloseTarget 关闭一个目标的隔离连接，不会重建任何工作会话。
func (s *Service) CloseTarget(target string) {
	if s != nil && s.isolated != nil {
		s.isolated.CloseTarget(target)
	}
}

// Suspend 先关闭隔离连接并废弃旧 lease，供锁定或密钥变更建立不可派发边界。
func (s *Service) Suspend() error {
	if s == nil || s.isolated == nil {
		return nil
	}
	return s.isolated.Suspend()
}

// Resume 在新的凭据状态可用后恢复隔离直接诊断。
func (s *Service) Resume() {
	if s != nil && s.isolated != nil {
		s.isolated.Resume()
	}
}

// CloseAll 关闭当前隔离连接；后续已解锁请求可以按当前身份重新建立连接。
func (s *Service) CloseAll() error {
	if s == nil || s.isolated == nil {
		return nil
	}
	return s.isolated.CloseAll()
}

// Close 永久关闭服务持有的隔离连接。
func (s *Service) Close() error {
	if s == nil || s.isolated == nil {
		return nil
	}
	return s.isolated.Close()
}

func (s *Service) executionEndpoint(ctx context.Context, vault *store.Vault, target store.SSHTarget) (store.SSHTarget, sshtransport.Endpoint, error) {
	if s == nil || s.store == nil {
		return store.SSHTarget{}, sshtransport.Endpoint{}, store.ErrInvalidTarget
	}
	current, err := s.store.SSHTarget(ctx, target.IP)
	if err != nil {
		return store.SSHTarget{}, sshtransport.Endpoint{}, err
	}
	if current.Revision != target.Revision {
		return store.SSHTarget{}, sshtransport.Endpoint{}, store.ErrTargetChanged
	}
	// Identity status is recorded for diagnostics and configuration workflows,
	// but it is not an execution gate. The transport still verifies the pinned
	// host key for this connection and reports a mismatch as a connection error.
	endpoint, err := s.endpoint(ctx, vault, current, nil)
	if err != nil {
		return store.SSHTarget{}, sshtransport.Endpoint{}, err
	}
	fingerprint, err := s.store.HostKeyFingerprint(ctx, endpoint.Host, endpoint.Port)
	if err != nil {
		secret.Zero(endpoint.Password)
		return store.SSHTarget{}, sshtransport.Endpoint{}, err
	}
	endpoint.Fingerprint = fingerprint
	return current, endpoint, nil
}
