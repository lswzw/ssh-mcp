package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/control"
	"ssh-mcp/internal/dbservice"
	"ssh-mcp/internal/dbtransport"
	"ssh-mcp/internal/instance"
	"ssh-mcp/internal/ipc"
	"ssh-mcp/internal/paths"
	"ssh-mcp/internal/runner"
	"ssh-mcp/internal/session"
	"ssh-mcp/internal/sshservice"
	"ssh-mcp/internal/store"
	"ssh-mcp/internal/terminal"
	"ssh-mcp/internal/tui"
	"ssh-mcp/internal/worksession"
)

const (
	stateFileName         = "state.db"
	instanceLockName      = "instance.lock"
	controlSockName       = "control.sock"
	bridgeSockName        = "bridge.sock"
	daemonPIDName         = "daemon.pid"
	daemonIdleTimeout     = time.Hour
	tuiConnectTimeout     = 5 * time.Second
	forceStopAuditTimeout = time.Second
)

var (
	ErrAlreadyRunning       = instance.ErrAlreadyRunning
	ErrMaintenanceBusy      = errors.New("exclusive maintenance requires no active bridge sessions")
	ErrTUIConnectionTimeout = bridge.ErrTUIConnectionTimeout
)

type RuntimeOptions struct {
	Roots             paths.Roots
	DaemonIdleTimeout time.Duration
	TUIConnectTimeout time.Duration
	TerminalSpec      string
	TUIOpener         func() error
	daemonStarter     func(context.Context) error
	sshDialer         sshservice.IsolatedDialer
}

type targetAuthorizationRevoker struct {
	workSessions       *worksession.Store
	sshConnections     sshConnectionCloser
	databaseAuthorizer *runner.DatabaseTargetAuthorizer
}

type sshConnectionCloser interface {
	InvalidateTarget(string)
	ActivateTarget(string)
	CloseTarget(string)
	Suspend() error
	Resume()
	CloseAll() error
	Close() error
}

func (r targetAuthorizationRevoker) RevokeSSHTarget(target string) {
	if r.sshConnections != nil {
		r.sshConnections.InvalidateTarget(target)
	}
	if r.workSessions != nil {
		r.workSessions.ClearTarget(target)
	}
}

// ActivateSSHTarget 在控制层完成目标配置更新后重新开放新的执行快照。
func (r targetAuthorizationRevoker) ActivateSSHTarget(target string) {
	if r.sshConnections != nil {
		r.sshConnections.ActivateTarget(target)
	}
}

func (r targetAuthorizationRevoker) RevokeDatabaseTarget(target string) {
	if r.databaseAuthorizer != nil {
		r.databaseAuthorizer.RevokeTarget(target)
	}
}

// ActivateDatabaseTarget 仅在控制层结束配置变更后允许新的数据库请求派发。
func (r targetAuthorizationRevoker) ActivateDatabaseTarget(target string) {
	if r.databaseAuthorizer != nil {
		r.databaseAuthorizer.ActivateTarget(target)
	}
}

// Runtime owns all local security-sensitive state for one MCP process.
type Runtime struct {
	roots             paths.Roots
	store             *store.Store
	audit             *auditlog.Logger
	control           *control.Service
	sessions          *session.Manager
	runner            *runner.Engine
	workSessions      *worksession.Store
	ssh               *sshservice.Service
	ipc               *ipc.Server
	bridge            *bridge.Server
	socketPath        string
	bridgeSocketPath  string
	daemonPIDPath     string
	desktopEnvPath    string
	daemonIdleTimeout time.Duration
	tuiConnectTimeout time.Duration
	terminalSpec      string
	openTUI           func() error
	instanceLock      *instance.Lock
	controlToken      string
	daemonPIDMarker   daemonPIDMarker

	mu                sync.Mutex
	started           bool
	closed            bool
	tuiLaunching      bool
	tuiActive         bool
	tuiLastHeartbeat  time.Time
	maintenanceActive bool
	sshLifecycleMu    sync.Mutex
	sessionID         string
	auditUser         string
	lastActivity      time.Time
	activeRequests    int
	desktopEnv        desktopEnvironment
	shutdownRequested chan struct{}
	shutdownOnce      sync.Once
}

func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	roots := options.Roots
	if roots.ConfigDir == "" || roots.RuntimeDir == "" {
		var err error
		roots, err = paths.Default()
		if err != nil {
			return nil, err
		}
	}
	desktopEnvPath := filepath.Join(roots.RuntimeDir, desktopEnvironmentFileName)
	desktopEnv, err := loadDesktopEnvironment(desktopEnvPath)
	if err != nil {
		return nil, err
	}
	processLock, err := instance.Acquire(filepath.Join(roots.ConfigDir, instanceLockName))
	if err != nil {
		return nil, fmt.Errorf("acquire ssh-mcp instance lock: %w", err)
	}
	credentialStore, err := store.Open(filepath.Join(roots.ConfigDir, stateFileName))
	if err != nil {
		_ = processLock.Close()
		return nil, err
	}
	daemonIdle := options.DaemonIdleTimeout
	if daemonIdle <= 0 {
		daemonIdle = daemonIdleTimeout
	}
	tuiTimeout := options.TUIConnectTimeout
	if tuiTimeout <= 0 {
		tuiTimeout = tuiConnectTimeout
	}
	now := clock.Now()
	sessionID, err := newAuditSessionID()
	if err != nil {
		_ = credentialStore.Close()
		_ = processLock.Close()
		return nil, err
	}
	if err := credentialStore.CreateSession(context.Background(), store.SessionRecord{
		ID: sessionID, State: store.SessionLocked, CreatedAt: now, LastActivityAt: now, ExpiresAt: now.Add(daemonIdle),
	}); err != nil {
		_ = credentialStore.Close()
		_ = processLock.Close()
		return nil, err
	}
	controlToken, err := ipc.NewToken()
	if err != nil {
		_ = credentialStore.Close()
		_ = processLock.Close()
		return nil, fmt.Errorf("generate local control token: %w", err)
	}
	manager := session.NewManager(credentialStore)
	ssh := sshservice.New(credentialStore, sshservice.NativeTransport{})
	if options.sshDialer != nil {
		ssh = sshservice.NewWithIsolatedDialer(credentialStore, sshservice.NativeTransport{}, options.sshDialer)
	}
	workSessions := worksession.New(worksession.Options{Now: clock.Now, OnInvalidated: func(session worksession.Session) {
		ssh.CloseTarget(session.Target)
	}})
	databaseAuthorizer := runner.NewDatabaseTargetAuthorizerWithNow(clock.Now)
	dispatchBarrier := runner.NewDispatchBarrier()
	auditUser := currentAuditUser()
	audit := auditlog.New(filepath.Join(roots.ConfigDir, auditlog.FileName))
	controlService := control.NewService(credentialStore, manager, control.WithTargetAuthorizationRevoker(targetAuthorizationRevoker{
		workSessions: workSessions, sshConnections: ssh, databaseAuthorizer: databaseAuthorizer,
	}), control.WithAuditor(audit), control.WithAuditActor(auditlog.Actor{User: auditUser, Source: "tui-control"}), control.WithDispatchLeaseAcquirer(func() control.DispatchLease {
		return dispatchBarrier.Acquire()
	}))
	socketPath := filepath.Join(roots.RuntimeDir, controlSockName)
	bridgeSocketPath := filepath.Join(roots.RuntimeDir, bridgeSockName)
	daemonPIDPath := filepath.Join(roots.RuntimeDir, daemonPIDName)
	runtime := &Runtime{
		roots:             roots,
		store:             credentialStore,
		audit:             audit,
		control:           controlService,
		sessions:          manager,
		ssh:               ssh,
		socketPath:        socketPath,
		bridgeSocketPath:  bridgeSocketPath,
		daemonPIDPath:     daemonPIDPath,
		desktopEnvPath:    desktopEnvPath,
		daemonIdleTimeout: daemonIdle,
		tuiConnectTimeout: tuiTimeout,
		terminalSpec:      options.TerminalSpec,
		instanceLock:      processLock,
		controlToken:      controlToken,
		sessionID:         sessionID,
		auditUser:         auditUser,
		lastActivity:      now,
		desktopEnv:        desktopEnv,
		shutdownRequested: make(chan struct{}),
	}
	runtime.ipc = ipc.NewServer(ipc.ServerOptions{
		SocketPath: socketPath, Token: controlToken,
		Handler: ipc.HandlerFunc(runtime.handleControl),
	})
	if options.TUIOpener != nil {
		runtime.openTUI = options.TUIOpener
	} else {
		runtime.openTUI = runtime.OpenTUI
	}
	runtime.workSessions = workSessions
	runtime.runner = runner.New(runner.Dependencies{
		Targets: credentialStore, Sessions: manager,
		SSH: ssh, FileReader: ssh, Deployer: ssh,
		Database:     dbservice.New(credentialStore, dbtransport.NativeTransport{}),
		WorkSessions: workSessions, DatabaseAuthorizer: databaseAuthorizer, DispatchBarrier: dispatchBarrier, Audit: runtime.audit,
		OpenTUI: runtime.requestTUI, SessionID: sessionID, AuditActor: auditlog.Actor{User: auditUser, Source: "daemon"},
	})
	runtime.bridge = bridge.NewServer(bridge.ServerOptions{
		SocketPath: bridgeSocketPath,
		Handler:    bridge.HandlerFunc(runtime.handleBridge),
		SessionClosed: func(session bridge.Session) {
			runtime.clearBridgeOwner(session.OwnerID)
		},
	})
	return runtime, nil
}

// requestShutdown asks the daemon loop to leave its serving state after the
// current bridge response has been written. The bridge capability check is
// performed by the caller before this method is reached.
func (r *Runtime) requestShutdown() {
	if r == nil {
		return
	}
	r.shutdownOnce.Do(func() {
		if r.shutdownRequested != nil {
			close(r.shutdownRequested)
		}
	})
}

// requestShutdownAfterResponse waits for the local transport to finish the
// current bridge response. Closing the daemon before that write completes
// turns an acknowledged stop request into a client-side transport failure.
func (r *Runtime) requestShutdownAfterResponse(ctx context.Context) {
	if r == nil || ctx == nil {
		return
	}
	go func() {
		<-ctx.Done()
		r.requestShutdown()
	}()
}

func (r *Runtime) clearBridgeOwner(ownerID string) {
	if r == nil {
		return
	}
	if r.workSessions != nil {
		r.workSessions.ClearOwner(ownerID)
	}
}

func (r *Runtime) requestTUI() error {
	if r.openTUI == nil {
		return r.OpenTUI()
	}
	return r.openTUI()
}

func (r *Runtime) Start() error {
	r.mu.Lock()
	if r.closed || r.started {
		r.mu.Unlock()
		return fmt.Errorf("runtime is not startable")
	}
	r.mu.Unlock()
	if err := r.ipc.Start(); err != nil {
		return err
	}
	if err := r.bridge.Start(); err != nil {
		_ = r.ipc.Close()
		return err
	}
	marker, err := writeDaemonPID(r.daemonPIDPath, os.Getpid())
	if err != nil {
		_ = r.bridge.Close()
		_ = r.ipc.Close()
		return err
	}
	r.mu.Lock()
	r.daemonPIDMarker = marker
	r.started = true
	r.mu.Unlock()
	return nil
}

func currentAuditUser() string {
	current, err := user.Current()
	if err == nil && current.Username != "" {
		return current.Username
	}
	if value := os.Getenv("USERNAME"); value != "" {
		return value
	}
	if value := os.Getenv("USER"); value != "" {
		return value
	}
	return platformAuditUserFallback()
}

func (r *Runtime) auditActor(session bridge.Session) auditlog.Actor {
	actor := auditlog.Actor{User: r.auditUser, Source: "codex-mcp", PID: session.PID, WorkingDirectory: session.WorkingDirectory, BridgeSessionID: session.ID}
	if actor.User == "" {
		actor.User = currentAuditUser()
	}
	return actor
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	started := r.started
	marker := r.daemonPIDMarker
	r.invalidateControlTokenLocked(r.controlToken)
	r.mu.Unlock()

	var closeErrors []error
	r.sshLifecycleMu.Lock()
	defer r.sshLifecycleMu.Unlock()
	if r.runner != nil {
		closeErrors = append(closeErrors, r.runner.LockDispatch(context.Background()))
	}
	if r.ssh != nil {
		closeErrors = append(closeErrors, r.ssh.Suspend())
	}
	r.control.Close()
	if r.ssh != nil {
		closeErrors = append(closeErrors, r.ssh.Close())
	}
	r.workSessions.Clear()
	if started {
		closeErrors = append(closeErrors, r.bridge.Close(), r.ipc.Close(), removeDaemonPID(r.daemonPIDPath, marker))
	}
	if r.audit != nil {
		closeErrors = append(closeErrors, r.audit.Close())
	}
	closeErrors = append(closeErrors, r.store.Close(), r.instanceLock.Close())
	return errors.Join(closeErrors...)
}

func (r *Runtime) SocketPath() string {
	return r.socketPath
}

func (r *Runtime) BridgeSocketPath() string {
	return r.bridgeSocketPath
}

func (r *Runtime) ActiveBridgeSessions() int {
	return r.bridge.ActiveSessions()
}

func (r *Runtime) WaitForIdle(ctx context.Context) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.hasActiveTUI(clock.Now()) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
			continue
		}
		r.mu.Lock()
		lastActivity := r.lastActivity
		activeRequests := r.activeRequests
		r.mu.Unlock()
		if activeRequests == 0 && time.Since(lastActivity) >= r.daemonIdleTimeout {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Runtime) handleControl(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "tui.connected":
		r.setTUIActivity(clock.Now())
		r.touchActivity(clock.Now())
		return struct{}{}, nil
	case "tui.heartbeat":
		r.setTUIActivity(clock.Now())
		return struct{}{}, nil
	case "tui.disconnected":
		r.clearTUIActivity(clock.Now())
		return struct{}{}, nil
	case "backup.restore", "keys.rotate", "keys.change_master_password":
		r.touchActivity(clock.Now())
		result, err := r.withExclusiveMaintenance(func() (any, error) {
			if method != "keys.rotate" && method != "keys.change_master_password" {
				return r.control.Handle(ctx, method, params)
			}
			r.sshLifecycleMu.Lock()
			defer r.sshLifecycleMu.Unlock()
			if r.ssh != nil {
				_ = r.ssh.Suspend()
			}
			result, err := r.control.Handle(ctx, method, params)
			if err != nil {
				if r.ssh != nil {
					r.ssh.Resume()
				}
				return result, err
			}
			r.sessions.Lock()
			r.workSessions.Clear()
			return result, nil
		})
		return result, err
	case "lock":
		r.touchActivity(clock.Now())
		if err := r.runner.LockDispatch(ctx); err != nil {
			r.runner.UnlockDispatch()
			return nil, err
		}
		lockedDispatch := true
		defer func() {
			if lockedDispatch {
				r.runner.UnlockDispatch()
			}
		}()
		r.sshLifecycleMu.Lock()
		defer r.sshLifecycleMu.Unlock()
		if r.ssh != nil {
			_ = r.ssh.Suspend()
		}
		result, err := r.control.Handle(ctx, method, params)
		if err != nil {
			if r.ssh != nil {
				r.ssh.Resume()
			}
			return result, err
		}
		r.workSessions.Clear()
		lockedDispatch = false
		return result, nil
	case "unlock":
		r.touchActivity(clock.Now())
		r.sshLifecycleMu.Lock()
		defer r.sshLifecycleMu.Unlock()
		result, err := r.control.Handle(ctx, method, params)
		if err == nil {
			if r.ssh != nil {
				r.ssh.Resume()
			}
			r.runner.UnlockDispatch()
		}
		return result, err
	default:
		r.touchActivity(clock.Now())
		return r.control.Handle(ctx, method, params)
	}
}

func (r *Runtime) touchActivity(now time.Time) {
	r.mu.Lock()
	if r.started && !r.closed {
		r.lastActivity = now
	}
	r.mu.Unlock()
}

func (r *Runtime) beginBridgeRequest() func() {
	r.mu.Lock()
	if r.started && !r.closed {
		r.lastActivity = clock.Now()
		r.activeRequests++
	}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if r.activeRequests > 0 {
			r.activeRequests--
		}
		r.mu.Unlock()
	}
}

func (r *Runtime) withExclusiveMaintenance(operation func() (any, error)) (any, error) {
	if r.ActiveBridgeSessions() > 0 {
		return nil, ErrMaintenanceBusy
	}
	r.mu.Lock()
	if r.maintenanceActive {
		r.mu.Unlock()
		return nil, ErrMaintenanceBusy
	}
	r.maintenanceActive = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.maintenanceActive = false
		r.mu.Unlock()
	}()
	return operation()
}

func (r *Runtime) maintenanceInProgress() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maintenanceActive
}

func (r *Runtime) setTUIActivity(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started && !r.closed {
		r.tuiLaunching = false
		r.tuiActive = true
		r.tuiLastHeartbeat = now
	}
}

func (r *Runtime) clearTUIActivity(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token := r.controlToken
	r.tuiLaunching = false
	r.tuiActive = false
	r.tuiLastHeartbeat = time.Time{}
	if r.started && !r.closed {
		r.lastActivity = now
	}
	r.invalidateControlTokenLocked(token)
}

func (r *Runtime) hasActiveTUI(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.tuiActive {
		return false
	}
	if now.Sub(r.tuiLastHeartbeat) <= 10*time.Second {
		return true
	}
	token := r.controlToken
	r.tuiLaunching = false
	r.tuiActive = false
	r.tuiLastHeartbeat = time.Time{}
	if r.started && !r.closed {
		r.lastActivity = now
	}
	r.invalidateControlTokenLocked(token)
	return false
}

func (r *Runtime) handleBridge(ctx context.Context, bridgeSession bridge.Session, method string, params json.RawMessage) (any, error) {
	finish := r.beginBridgeRequest()
	defer finish()
	switch method {
	case bridgeMethodStatus:
		status, err := r.control.Handle(ctx, "status", nil)
		if err != nil {
			return nil, err
		}
		active := r.ActiveBridgeSessions()
		if active > 0 {
			active--
		}
		return DaemonStatus{Running: true, Control: status.(control.Status), ActiveBridgeSessions: active}, nil
	case bridgeMethodPrepareForceStop:
		return r.prepareForceStop(ctx), nil
	case bridgeMethodShutdown:
		r.requestShutdownAfterResponse(ctx)
		return struct{}{}, nil
	case bridgeMethodOpenTUI:
		var request openTUIRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		if err := r.setDesktopEnvironment(request.DesktopEnvironment); err != nil {
			return nil, err
		}
		waitContext, cancel := context.WithTimeout(ctx, r.tuiConnectTimeout)
		defer cancel()
		if err := r.OpenTUIAndWait(waitContext); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	}
	if r.maintenanceInProgress() {
		return nil, ErrMaintenanceBusy
	}
	switch method {
	case bridgeMethodListTargets:
		return r.runner.ListTargets(ctx)
	case bridgeMethodDescribeTarget:
		var request runner.ExecutionSpecificationRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.describeExecutionSpecificationForBridge(ctx, request)
	case bridgeMethodListDatabases:
		var request runner.DatabaseListRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.listDatabasesForBridge(ctx, bridgeSession, request)
	case bridgeMethodRunSSH:
		var request runner.SSHRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.runSSHForBridge(ctx, bridgeSession, request)
	case bridgeMethodReadSSHFile:
		var request runner.SSHFileReadRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.readSSHFileForBridge(ctx, bridgeSession, request)
	case bridgeMethodDeploySSHBinary:
		var request runner.SSHBinaryDeploymentRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.deploySSHBinaryForBridge(ctx, bridgeSession, request)
	case bridgeMethodOpenSSHSession:
		var request runner.OpenSSHSessionRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.openSSHSessionForBridge(ctx, bridgeSession, request)
	case bridgeMethodSetSSHSession:
		var request runner.SetSSHSessionContextRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.setSSHSessionContextForBridge(ctx, bridgeSession, request)
	case bridgeMethodExecuteSSHSession:
		var request runner.ExecuteSSHSessionRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.executeSSHSessionForBridge(ctx, bridgeSession, request)
	case bridgeMethodCloseSSHSession:
		var request closeSSHSessionRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.closeSSHSessionForBridge(ctx, bridgeSession, request.SessionID)
	case bridgeMethodRunSQL:
		var request runner.SQLRequest
		if err := json.Unmarshal(params, &request); err != nil {
			return nil, bridge.ErrInvalidRequest
		}
		return r.runSQLForBridge(ctx, bridgeSession, request)
	default:
		return nil, bridge.ErrMethodNotFound
	}
}

// prepareForceStop 只记录强制停机风险并封闭新派发；它不能等待或恢复在途远端操作。
func (r *Runtime) prepareForceStop(ctx context.Context) struct{} {
	if r == nil {
		return struct{}{}
	}
	if r.runner != nil {
		r.runner.BlockDispatch()
	}
	if r.audit == nil {
		return struct{}{}
	}
	auditContext, cancel := context.WithTimeout(ctx, forceStopAuditTimeout)
	defer cancel()
	// 强制停止继续执行，即使本地追溯写入失败也不会伪装为可安全恢复。
	_ = r.audit.Record(auditContext, auditlog.Event{
		Time:   clock.InBeijing(clock.Now()),
		Phase:  auditlog.PhaseFailed,
		Action: "daemon_force_stop",
		Actor:  auditlog.Actor{User: currentAuditUser(), Source: "daemon-control"},
		Target: auditlog.Target{Kind: "daemon", ID: "local"},
		Result: auditlog.Result{Status: runner.StatusOutcomeUnknown, Summary: "in_flight_operations_may_be_unknown"},
	})
	return struct{}{}
}

func writeDaemonPID(path string, pid int) (daemonPIDMarker, error) {
	startTime, err := bridge.ProcessStartTime(pid)
	if err != nil {
		return daemonPIDMarker{}, fmt.Errorf("resolve daemon process identity: %w", err)
	}
	marker := daemonPIDMarker{PID: pid, StartTime: startTime}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return daemonPIDMarker{}, fmt.Errorf("daemon PID file must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return daemonPIDMarker{}, fmt.Errorf("inspect daemon PID file: %w", err)
	}
	directory := filepath.Dir(path)
	if err := paths.EnsureDirectory(directory); err != nil {
		return daemonPIDMarker{}, fmt.Errorf("prepare daemon PID directory: %w", err)
	}
	file, err := paths.CreateTemp(directory, ".ssh-mcp-daemon-pid-*")
	if err != nil {
		return daemonPIDMarker{}, fmt.Errorf("create daemon PID file: %w", err)
	}
	temporaryPath := file.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := file.WriteString(formatDaemonPID(marker)); err != nil {
		_ = file.Close()
		return daemonPIDMarker{}, fmt.Errorf("write daemon PID file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return daemonPIDMarker{}, fmt.Errorf("sync daemon PID file: %w", err)
	}
	if err := file.Close(); err != nil {
		return daemonPIDMarker{}, fmt.Errorf("close daemon PID file: %w", err)
	}
	if err := paths.ReplaceFile(temporaryPath, path); err != nil {
		return daemonPIDMarker{}, fmt.Errorf("replace daemon PID file: %w", err)
	}
	if err := paths.SyncDirectory(directory); err != nil {
		return daemonPIDMarker{}, fmt.Errorf("sync daemon PID directory: %w", err)
	}
	if err := paths.EnsureRegularFile(path); err != nil {
		return daemonPIDMarker{}, fmt.Errorf("verify daemon PID file: %w", err)
	}
	return marker, nil
}

func removeDaemonPID(path string, expected daemonPIDMarker) error {
	marker, err := readDaemonPID(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Never remove a marker whose identity cannot be parsed. A newer daemon
		// may have replaced it, or the file may have been tampered with.
		if errors.Is(err, errDaemonPIDMarker) {
			return nil
		}
		return fmt.Errorf("read daemon PID file: %w", err)
	}
	if marker != expected {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove daemon PID file: %w", err)
	}
	return nil
}

// Token is an ephemeral capability held only by this Runtime and the TUI it
// launches. It is intentionally never persisted in the local state database.
func (r *Runtime) Token() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.controlToken
}

type tuiLaunch struct {
	socketPath   string
	terminalSpec string
	token        string
}

func (r *Runtime) beginTUILaunch() (tuiLaunch, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.closed {
		return tuiLaunch{}, false, fmt.Errorf("runtime is not running")
	}
	if r.tuiLaunching || r.tuiActive {
		return tuiLaunch{}, true, nil
	}
	token, err := r.rotateControlTokenLocked()
	if err != nil {
		return tuiLaunch{}, false, err
	}
	r.tuiLaunching = true
	return tuiLaunch{socketPath: r.socketPath, terminalSpec: r.terminalSpec, token: token}, false, nil
}

func (r *Runtime) rotateControlTokenLocked() (string, error) {
	if r.ipc == nil {
		return "", fmt.Errorf("local control server is unavailable")
	}
	token, err := ipc.NewToken()
	if err != nil {
		return "", fmt.Errorf("generate local control token: %w", err)
	}
	if err := r.ipc.SetToken(token); err != nil {
		return "", fmt.Errorf("rotate local control token: %w", err)
	}
	r.controlToken = token
	return token, nil
}

// invalidateControlTokenLocked revokes the token only when it still belongs
// to the TUI lifecycle that requested invalidation. Callers must hold r.mu.
func (r *Runtime) invalidateControlTokenLocked(expected string) {
	if expected == "" || r.controlToken != expected {
		return
	}
	if r.ipc != nil {
		r.ipc.DisableToken()
	}
	r.controlToken = ""
}

func newAuditSessionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate audit session ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// OpenTUI 启动本地交互式控制进程，供本地解锁或目标配置流程使用。
func (r *Runtime) OpenTUI() error {
	launch, alreadyOpen, err := r.beginTUILaunch()
	if err != nil {
		return err
	}
	if alreadyOpen {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		r.clearTUILaunch(launch.token)
		return fmt.Errorf("resolve ssh-mcp executable: %w", err)
	}
	spec := launch.terminalSpec
	if spec == "" {
		spec = os.Getenv("SSH_MCP_TERMINAL")
	}
	launcher, err := terminal.Resolve(spec)
	if err != nil {
		r.clearTUILaunch(launch.token)
		return err
	}
	if err := launcher.StartWithEnvironment(r.tuiCommandEnvironment(), executable, "tui", "--socket", launch.socketPath, "--token", launch.token); err != nil {
		r.clearTUILaunch(launch.token)
		return err
	}
	time.AfterFunc(10*time.Second, func() { r.expireUnconnectedTUILaunch(launch.token) })
	return nil
}

// OpenTUIAndWait starts or reuses the local TUI and returns only after that
// process authenticated to the control socket. This lets `ssh-mcp manage`
// report launch failures instead of silently returning after a signal.
func (r *Runtime) OpenTUIAndWait(ctx context.Context) error {
	if r.hasActiveTUI(clock.Now()) {
		return nil
	}
	if err := r.requestTUI(); err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.hasActiveTUI(clock.Now()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrTUIConnectionTimeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (r *Runtime) setDesktopEnvironment(environment desktopEnvironment) error {
	if environment.empty() {
		return nil
	}
	if err := saveDesktopEnvironment(r.desktopEnvPath, environment); err != nil {
		return err
	}
	r.mu.Lock()
	changed := r.desktopEnv != environment
	r.desktopEnv = environment
	if changed && !r.tuiActive {
		r.tuiLaunching = false
	}
	r.mu.Unlock()
	return nil
}

func (r *Runtime) desktopEnvironment() desktopEnvironment {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.desktopEnv
}

func (r *Runtime) tuiCommandEnvironment() []string {
	return r.desktopEnvironment().commandEnvironment(os.Environ())
}

func (r *Runtime) clearTUILaunch(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.controlToken != token || r.tuiActive {
		return
	}
	r.tuiLaunching = false
	r.invalidateControlTokenLocked(token)
}

func (r *Runtime) expireUnconnectedTUILaunch(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.controlToken != token || r.tuiActive {
		return
	}
	r.tuiLaunching = false
	r.invalidateControlTokenLocked(token)
}

func RunTUI(ctx context.Context, socketPath, token string) error {
	if socketPath == "" {
		return fmt.Errorf("TUI requires a local socket")
	}
	if err := callTUIControl(socketPath, token, "tui.connected"); err != nil {
		return err
	}
	heartbeatContext, cancelHeartbeat := context.WithCancel(context.Background())
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatContext.Done():
				return
			case <-ticker.C:
				_ = callTUIControl(socketPath, token, "tui.heartbeat")
			}
		}
	}()
	defer func() {
		cancelHeartbeat()
		<-heartbeatDone
		_ = callTUIControl(socketPath, token, "tui.disconnected")
	}()
	return tui.Run(ctx, socketPath, token)
}

func callTUIControl(socketPath, token, method string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ipc.NewClient(socketPath, token).Call(ctx, method, nil, &struct{}{})
}
