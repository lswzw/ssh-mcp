package sshservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"ssh-mcp/internal/sshtransport"
)

// IsolatedConnection 是不保存工作目录、环境或命令状态的已认证 SSH 连接。
type IsolatedConnection interface {
	Execute(context.Context, string, bool, int) (sshtransport.ExecutionResult, error)
	Close() error
}

// isolatedFileReader is intentionally narrower than IsolatedConnection. Only
// native pinned SSH clients implement it; command-only test and extension
// connections remain valid without acquiring file access by accident.
type isolatedFileReader interface {
	ReadFile(context.Context, string, int64, int) (sshtransport.FileReadResult, error)
}

// isolatedBinaryDeployer is intentionally narrower than IsolatedConnection.
// It exposes only the transport's controlled deployment transaction; callers
// cannot obtain a generic SFTP writer or arbitrary remote command through it.
type isolatedBinaryDeployer interface {
	DeployBinary(context.Context, io.Reader, sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error)
}

var _ isolatedBinaryDeployer = (*sshtransport.Client)(nil)

// IsolatedDialer 建立可复用的物理连接。每条命令仍通过独立 SSH channel 执行。
type IsolatedDialer interface {
	Dial(context.Context, sshtransport.Endpoint) (IsolatedConnection, error)
}

type nativeIsolatedDialer struct{}

func (nativeIsolatedDialer) Dial(ctx context.Context, endpoint sshtransport.Endpoint) (IsolatedConnection, error) {
	return sshtransport.Dial(ctx, endpoint)
}

type isolatedConnectionKey struct {
	Target               string
	TargetRevision       int64
	Port                 int
	Username             string
	CredentialID         string
	Fingerprint          string
	SpecificationVersion string
}

type isolatedConnectionEntry struct {
	key         isolatedConnectionKey
	ready       chan struct{}
	readyClosed bool
	connection  IsolatedConnection
	dialing     bool
	dialCancel  context.CancelFunc
	invalidated bool
	closed      bool
}

// isolatedTargetGate 保存目标授权代际和正在执行的直接诊断数量。配置变更会推进代际，
// 因而已读取旧配置的请求即使稍后才拿到连接，也无法发出命令。
type isolatedTargetGate struct {
	generation           uint64
	configurationBlocked bool
	lifecycleFlushes     int
	inFlight             int
	idle                 chan struct{}
}

// isolatedTargetLease 只代表一次直接诊断的目标授权窗口，不保存连接或会话状态。
type isolatedTargetLease struct {
	pool       *isolatedConnectionPool
	target     string
	generation uint64
}

type isolatedTargetFlush struct {
	target  string
	gate    *isolatedTargetGate
	wait    <-chan struct{}
	release bool
}

type isolatedConnectionPool struct {
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	dialer      IsolatedDialer
	entries     map[isolatedConnectionKey]*isolatedConnectionEntry
	targets     map[string]*isolatedTargetGate
	suspended   bool
	closed      bool
}

func newIsolatedConnectionPool(dialer IsolatedDialer) *isolatedConnectionPool {
	if dialer == nil {
		dialer = nativeIsolatedDialer{}
	}
	return &isolatedConnectionPool{
		dialer:  dialer,
		entries: make(map[isolatedConnectionKey]*isolatedConnectionEntry),
		targets: make(map[string]*isolatedTargetGate),
	}
}

// AcquireTarget 在读取目标配置前取得一次性的派发 lease。撤销后旧 lease 永远不可用。
func (p *isolatedConnectionPool) AcquireTarget(target string) (*isolatedTargetLease, error) {
	if p == nil {
		return nil, notDispatched(errors.New("isolated SSH connection pool is unavailable"))
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, notDispatched(errors.New("isolated SSH target is empty"))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.suspended {
		return nil, notDispatched(errors.New("isolated SSH connection pool is closed"))
	}
	gate := p.targetGateLocked(target)
	if gate.blocked() {
		return nil, notDispatched(errors.New("isolated SSH target is being reconfigured"))
	}
	return &isolatedTargetLease{pool: p, target: target, generation: gate.generation}, nil
}

// Execute 保留连接池内部调用的便利入口；服务层应在读取配置前先取得 lease。
func (p *isolatedConnectionPool) Execute(ctx context.Context, key isolatedConnectionKey, endpoint sshtransport.Endpoint, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	lease, err := p.AcquireTarget(key.Target)
	if err != nil {
		return sshtransport.ExecutionResult{}, err
	}
	return lease.Execute(ctx, key, endpoint, command, asRoot, maxBytes)
}

// Execute 仅在 lease 仍属于当前目标代际时才会调用物理 SSH 连接。
func (l *isolatedTargetLease) Execute(ctx context.Context, key isolatedConnectionKey, endpoint sshtransport.Endpoint, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	if l == nil || l.pool == nil || strings.TrimSpace(key.Target) != l.target {
		return sshtransport.ExecutionResult{}, notDispatched(errors.New("isolated SSH target lease does not match the execution target"))
	}
	return l.pool.execute(ctx, l, key, endpoint, command, asRoot, maxBytes)
}

// ReadFile uses the same target lease, generation and pinned physical
// connection lifecycle as isolated SSH commands, but only when that
// connection exposes the constrained read-only file protocol.
func (l *isolatedTargetLease) ReadFile(ctx context.Context, key isolatedConnectionKey, endpoint sshtransport.Endpoint, remotePath string, offset int64, maxBytes int) (sshtransport.FileReadResult, error) {
	if l == nil || l.pool == nil || strings.TrimSpace(key.Target) != l.target {
		return sshtransport.FileReadResult{}, notDispatched(errors.New("isolated SSH target lease does not match the file read target"))
	}
	return l.pool.readFile(ctx, l, key, endpoint, remotePath, offset, maxBytes)
}

// DeployBinary uses the same target lease, generation and pinned physical
// connection lifecycle as isolated SSH commands. The concrete connection
// must explicitly implement the controlled binary deployment capability.
func (l *isolatedTargetLease) DeployBinary(ctx context.Context, key isolatedConnectionKey, endpoint sshtransport.Endpoint, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	if l == nil || l.pool == nil || strings.TrimSpace(key.Target) != l.target {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(errors.New("isolated SSH target lease does not match the binary deployment target"))
	}
	return l.pool.deployBinary(ctx, l, key, endpoint, source, request)
}

func (p *isolatedConnectionPool) execute(ctx context.Context, lease *isolatedTargetLease, key isolatedConnectionKey, endpoint sshtransport.Endpoint, command string, asRoot bool, maxBytes int) (sshtransport.ExecutionResult, error) {
	if err := ctx.Err(); err != nil {
		return sshtransport.ExecutionResult{}, notDispatched(err)
	}
	entry, connection, err := p.acquire(ctx, lease, key, endpoint)
	if err != nil {
		return sshtransport.ExecutionResult{}, err
	}

	// 连接取得与取消信号可能同时就绪；再次检查可防止已超时请求派发命令。
	if err := ctx.Err(); err != nil {
		return sshtransport.ExecutionResult{}, notDispatched(err)
	}
	if !p.beginDispatch(lease, entry) {
		return sshtransport.ExecutionResult{}, notDispatched(errors.New("isolated SSH target was invalidated before dispatch"))
	}
	defer p.finishInFlight(lease.target)
	if err := ctx.Err(); err != nil {
		return sshtransport.ExecutionResult{}, notDispatched(err)
	}

	result, err := connection.Execute(ctx, command, asRoot, maxBytes)
	if err != nil {
		p.discard(entry)
	}
	return result, err
}

func (p *isolatedConnectionPool) readFile(ctx context.Context, lease *isolatedTargetLease, key isolatedConnectionKey, endpoint sshtransport.Endpoint, remotePath string, offset int64, maxBytes int) (sshtransport.FileReadResult, error) {
	if err := ctx.Err(); err != nil {
		return sshtransport.FileReadResult{}, notDispatched(err)
	}
	entry, connection, err := p.acquire(ctx, lease, key, endpoint)
	if err != nil {
		return sshtransport.FileReadResult{}, err
	}
	reader, ok := connection.(isolatedFileReader)
	if !ok {
		return sshtransport.FileReadResult{}, notDispatched(errors.New("isolated SSH connection does not support constrained file inspection"))
	}
	if err := ctx.Err(); err != nil {
		return sshtransport.FileReadResult{}, notDispatched(err)
	}
	if !p.beginDispatch(lease, entry) {
		return sshtransport.FileReadResult{}, notDispatched(errors.New("isolated SSH target was invalidated before file read dispatch"))
	}
	defer p.finishInFlight(lease.target)
	if err := ctx.Err(); err != nil {
		return sshtransport.FileReadResult{}, notDispatched(err)
	}
	result, err := reader.ReadFile(ctx, remotePath, offset, maxBytes)
	if err != nil {
		p.discard(entry)
	}
	return result, err
}

func (p *isolatedConnectionPool) deployBinary(ctx context.Context, lease *isolatedTargetLease, key isolatedConnectionKey, endpoint sshtransport.Endpoint, source io.Reader, request sshtransport.BinaryDeploymentRequest) (sshtransport.BinaryDeploymentResult, error) {
	if err := ctx.Err(); err != nil {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(err)
	}
	entry, connection, err := p.acquire(ctx, lease, key, endpoint)
	if err != nil {
		return sshtransport.BinaryDeploymentResult{}, err
	}
	deployer, ok := connection.(isolatedBinaryDeployer)
	if !ok {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(errBinaryDeploymentUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(err)
	}
	if !p.beginDispatch(lease, entry) {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(errors.New("isolated SSH target was invalidated before binary deployment dispatch"))
	}
	defer p.finishInFlight(lease.target)
	if err := ctx.Err(); err != nil {
		return sshtransport.BinaryDeploymentResult{}, notDispatched(err)
	}
	result, err := deployer.DeployBinary(ctx, source, request)
	if err != nil {
		p.discard(entry)
	}
	return result, err
}

// InvalidateTarget 阻断新请求并让已经读取旧配置的 lease 失效。
func (p *isolatedConnectionPool) InvalidateTarget(target string) {
	p.invalidateTarget(target, true)
}

// ActivateTarget 仅在目标配置成功持久化后重新允许直接诊断。
func (p *isolatedConnectionPool) ActivateTarget(target string) {
	if p == nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	p.mu.Lock()
	if !p.closed {
		p.targetGateLocked(target).configurationBlocked = false
	}
	p.mu.Unlock()
}

// CloseTarget 关闭目标的连接但不阻断后续、重新授权的直接诊断。
func (p *isolatedConnectionPool) CloseTarget(target string) {
	p.invalidateTarget(target, false)
}

// Suspend 会使全部已有 lease 失效，并在凭据状态改变前关闭隔离连接。
// Resume 之前不会接受新的直接诊断，避免旧授权快照跨越锁定边界派发命令。
func (p *isolatedConnectionPool) Suspend() error {
	if p == nil {
		return nil
	}
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	p.mu.Lock()
	if p.closed || p.suspended {
		p.mu.Unlock()
		return nil
	}
	p.suspended = true
	connections := p.invalidateAllLocked()
	flushes := p.advanceAllTargetsLocked(false)
	p.mu.Unlock()

	closeErr := closeConnections(connections)
	for _, flush := range flushes {
		waitForTargetFlush(flush)
	}
	return closeErr
}

// Resume 只在新的凭据状态已经可用后重新允许隔离直接诊断。
func (p *isolatedConnectionPool) Resume() {
	if p == nil {
		return
	}
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	p.mu.Lock()
	if !p.closed {
		p.suspended = false
	}
	p.mu.Unlock()
}

func (p *isolatedConnectionPool) invalidateTarget(target string, remainBlocked bool) {
	if p == nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	p.mu.Lock()
	gate := p.targetGateLocked(target)
	gate.generation++
	if remainBlocked {
		gate.configurationBlocked = true
	} else {
		gate.lifecycleFlushes++
	}
	connections := p.invalidateTargetLocked(target)
	flush := isolatedTargetFlush{
		target: target, gate: gate, wait: p.waitForInFlightLocked(gate), release: !remainBlocked,
	}
	p.mu.Unlock()
	_ = closeConnections(connections)
	waitForTargetFlush(flush)
	if !remainBlocked {
		p.releaseTargetFlush(flush)
	}
}

// CloseAll 关闭当前隔离连接；后续已解锁请求可以按当前身份重新建立连接。
func (p *isolatedConnectionPool) CloseAll() error {
	if p == nil {
		return nil
	}
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	connections := p.invalidateAllLocked()
	flushes := p.advanceAllTargetsLocked(true)
	p.mu.Unlock()
	closeErr := closeConnections(connections)
	for _, flush := range flushes {
		waitForTargetFlush(flush)
	}
	for _, flush := range flushes {
		p.releaseTargetFlush(flush)
	}
	return closeErr
}

// Close 永久关闭服务持有的隔离连接。
func (p *isolatedConnectionPool) Close() error {
	if p == nil {
		return nil
	}
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	connections := p.invalidateAllLocked()
	flushes := p.advanceAllTargetsLocked(false)
	p.mu.Unlock()
	closeErr := closeConnections(connections)
	for _, flush := range flushes {
		waitForTargetFlush(flush)
	}
	return closeErr
}

func (p *isolatedConnectionPool) acquire(ctx context.Context, lease *isolatedTargetLease, key isolatedConnectionKey, endpoint sshtransport.Endpoint) (*isolatedConnectionEntry, IsolatedConnection, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, notDispatched(err)
		}
		p.mu.Lock()
		if !p.leaseValidLocked(lease) {
			p.mu.Unlock()
			return nil, nil, notDispatched(errors.New("isolated SSH target was invalidated before dispatch"))
		}
		entry := p.entries[key]
		if entry == nil {
			connections := p.invalidateOtherTargetEntriesLocked(key)
			dialContext, cancelDial := context.WithCancel(ctx)
			entry = &isolatedConnectionEntry{
				key: key, ready: make(chan struct{}), dialing: true, dialCancel: cancelDial,
			}
			p.entries[key] = entry
			p.beginInFlightLocked(lease.target)
			p.mu.Unlock()
			_ = closeConnections(connections)

			connection, dialErr := p.dialer.Dial(dialContext, endpoint)
			cancelDial()
			p.mu.Lock()
			entry.dialing = false
			entry.dialCancel = nil
			p.finishInFlightLocked(lease.target)
			if dialErr != nil {
				if p.entries[key] == entry {
					delete(p.entries, key)
				}
				entry.invalidated = true
				p.closeEntryReadyLocked(entry)
				p.mu.Unlock()
				return nil, nil, notDispatched(fmt.Errorf("dial isolated SSH connection: %w", dialErr))
			}
			entry.connection = connection
			invalidated := !p.leaseValidLocked(lease) || entry.invalidated || p.entries[key] != entry
			if invalidated {
				if p.entries[key] == entry {
					delete(p.entries, key)
				}
				entry.invalidated = true
				entry.closed = true
			}
			p.closeEntryReadyLocked(entry)
			p.mu.Unlock()
			if invalidated {
				_ = connection.Close()
				return nil, nil, notDispatched(errors.New("isolated SSH connection was invalidated before dispatch"))
			}
			continue
		}
		if entry.dialing {
			ready := entry.ready
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, nil, notDispatched(ctx.Err())
			case <-ready:
				continue
			}
		}
		p.mu.Unlock()

		if err := ctx.Err(); err != nil {
			return nil, nil, notDispatched(err)
		}
		p.mu.Lock()
		valid := p.leaseValidLocked(lease) && !entry.invalidated && p.entries[key] == entry && entry.connection != nil
		connection := entry.connection
		p.mu.Unlock()
		if !valid {
			return nil, nil, notDispatched(errors.New("isolated SSH connection was invalidated before dispatch"))
		}
		return entry, connection, nil
	}
}

func (p *isolatedConnectionPool) beginDispatch(lease *isolatedTargetLease, entry *isolatedConnectionEntry) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.leaseValidLocked(lease) || entry == nil || entry.invalidated || p.entries[entry.key] != entry || entry.connection == nil {
		return false
	}
	p.beginInFlightLocked(lease.target)
	return true
}

func (p *isolatedConnectionPool) finishInFlight(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.finishInFlightLocked(target)
}

func (p *isolatedConnectionPool) discard(entry *isolatedConnectionEntry) {
	if p == nil || entry == nil {
		return
	}
	p.mu.Lock()
	connection := p.invalidateEntryLocked(entry)
	p.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

func (p *isolatedConnectionPool) targetGateLocked(target string) *isolatedTargetGate {
	gate := p.targets[target]
	if gate == nil {
		gate = &isolatedTargetGate{}
		p.targets[target] = gate
	}
	return gate
}

func (p *isolatedConnectionPool) leaseValidLocked(lease *isolatedTargetLease) bool {
	if p.closed || p.suspended || lease == nil || lease.pool != p {
		return false
	}
	gate := p.targets[lease.target]
	return gate != nil && !gate.blocked() && gate.generation == lease.generation
}

func (p *isolatedConnectionPool) beginInFlightLocked(target string) {
	gate := p.targetGateLocked(target)
	if gate.inFlight == 0 {
		gate.idle = make(chan struct{})
	}
	gate.inFlight++
}

func (p *isolatedConnectionPool) finishInFlightLocked(target string) {
	gate := p.targets[target]
	if gate == nil || gate.inFlight == 0 {
		return
	}
	gate.inFlight--
	if gate.inFlight == 0 {
		close(gate.idle)
		gate.idle = nil
	}
}

func (p *isolatedConnectionPool) waitForInFlightLocked(gate *isolatedTargetGate) <-chan struct{} {
	if gate == nil || gate.inFlight == 0 {
		return nil
	}
	return gate.idle
}

func (p *isolatedConnectionPool) advanceAllTargetsLocked(temporary bool) []isolatedTargetFlush {
	flushes := make([]isolatedTargetFlush, 0, len(p.targets))
	for target, gate := range p.targets {
		gate.generation++
		if temporary {
			gate.lifecycleFlushes++
		}
		flushes = append(flushes, isolatedTargetFlush{
			target: target, gate: gate, wait: p.waitForInFlightLocked(gate), release: temporary,
		})
	}
	return flushes
}

func (p *isolatedConnectionPool) invalidateOtherTargetEntriesLocked(key isolatedConnectionKey) []IsolatedConnection {
	connections := make([]IsolatedConnection, 0)
	for existingKey, entry := range p.entries {
		if existingKey.Target == key.Target && existingKey != key {
			if connection := p.invalidateEntryLocked(entry); connection != nil {
				connections = append(connections, connection)
			}
		}
	}
	return connections
}

func (p *isolatedConnectionPool) invalidateTargetLocked(target string) []IsolatedConnection {
	connections := make([]IsolatedConnection, 0)
	for key, entry := range p.entries {
		if key.Target == target {
			if connection := p.invalidateEntryLocked(entry); connection != nil {
				connections = append(connections, connection)
			}
		}
	}
	return connections
}

func (p *isolatedConnectionPool) invalidateAllLocked() []IsolatedConnection {
	connections := make([]IsolatedConnection, 0, len(p.entries))
	for _, entry := range p.entries {
		if connection := p.invalidateEntryLocked(entry); connection != nil {
			connections = append(connections, connection)
		}
	}
	return connections
}

func (p *isolatedConnectionPool) invalidateEntryLocked(entry *isolatedConnectionEntry) IsolatedConnection {
	entry.invalidated = true
	if p.entries[entry.key] == entry {
		delete(p.entries, entry.key)
	}
	if entry.dialCancel != nil {
		entry.dialCancel()
	}
	p.closeEntryReadyLocked(entry)
	if entry.closed || entry.connection == nil {
		return nil
	}
	entry.closed = true
	return entry.connection
}

func (p *isolatedConnectionPool) closeEntryReadyLocked(entry *isolatedConnectionEntry) {
	if entry.readyClosed {
		return
	}
	close(entry.ready)
	entry.readyClosed = true
}

func closeConnections(connections []IsolatedConnection) error {
	var closeErrors []error
	for _, connection := range connections {
		if connection != nil {
			closeErrors = append(closeErrors, connection.Close())
		}
	}
	return errors.Join(closeErrors...)
}

func waitForInFlight(wait <-chan struct{}) {
	if wait != nil {
		<-wait
	}
}

func waitForTargetFlush(flush isolatedTargetFlush) {
	waitForInFlight(flush.wait)
}

func (p *isolatedConnectionPool) releaseTargetFlush(flush isolatedTargetFlush) {
	if !flush.release {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed && p.targets[flush.target] == flush.gate && flush.gate.lifecycleFlushes > 0 {
		flush.gate.lifecycleFlushes--
	}
}

func (g *isolatedTargetGate) blocked() bool {
	return g != nil && (g.configurationBlocked || g.lifecycleFlushes > 0)
}

func notDispatched(err error) error {
	if err == nil {
		err = errors.New("isolated SSH connection is unavailable")
	}
	return fmt.Errorf("%w: %w", sshtransport.ErrNotDispatched, err)
}
