package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"ssh-mcp/internal/auditlog"
	"ssh-mcp/internal/bridge"
	"ssh-mcp/internal/clock"
	"ssh-mcp/internal/policy"
	"ssh-mcp/internal/runner"
	"ssh-mcp/internal/store"
)

var (
	ErrTargetDisabled     = errors.New("target is disabled")
	ErrInvalidTargetInput = errors.New("target input is invalid")
)

func (r *Runtime) describeExecutionSpecificationForBridge(ctx context.Context, request runner.ExecutionSpecificationRequest) (runner.ExecutionSpecification, error) {
	return r.runner.DescribeExecutionSpecification(ctx, request)
}

func (r *Runtime) bridgeEngine(bridgeSession bridge.Session) *runner.Engine {
	return r.runner.WithAuditActor(r.auditActor(bridgeSession)).WithExecutionOwner(bridgeSession.OwnerID)
}

func (r *Runtime) listDatabasesForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.DatabaseListRequest) (runner.Result, error) {
	if err := r.waitForDatabaseTarget(ctx, request.Target); err != nil {
		if errors.Is(err, store.ErrTargetNotFound) {
			return r.missingTargetResult(ctx, bridgeSession, "database", request.Target, runner.StatusDatabaseNotFound)
		}
		if errors.Is(err, ErrTargetDisabled) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "database", request.Target, runner.StatusRejected, "target_disabled")
		}
		if errors.Is(err, ErrInvalidTargetInput) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "database", request.Target, runner.StatusRejected, "invalid_target")
		}
		return runner.Result{}, err
	}
	engine := r.bridgeEngine(bridgeSession)
	return engine.ListDatabases(ctx, request)
}

func (r *Runtime) runSSHForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.SSHRequest) (runner.Result, error) {
	if err := r.waitForSSHTarget(ctx, request.Target); err != nil {
		if errors.Is(err, store.ErrTargetNotFound) {
			return r.missingTargetResult(ctx, bridgeSession, "ssh", request.Target, runner.StatusTargetNotFound)
		}
		if errors.Is(err, ErrTargetDisabled) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "target_disabled")
		}
		if errors.Is(err, ErrInvalidTargetInput) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "invalid_target")
		}
		return runner.Result{}, err
	}
	engine := r.bridgeEngine(bridgeSession)
	return engine.RunSSH(ctx, request)
}

func (r *Runtime) readSSHFileForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.SSHFileReadRequest) (runner.Result, error) {
	if err := r.waitForSSHTarget(ctx, request.Target); err != nil {
		if errors.Is(err, store.ErrTargetNotFound) {
			return r.missingTargetResult(ctx, bridgeSession, "ssh", request.Target, runner.StatusTargetNotFound)
		}
		if errors.Is(err, ErrTargetDisabled) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "target_disabled")
		}
		if errors.Is(err, ErrInvalidTargetInput) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "invalid_target")
		}
		return runner.Result{}, err
	}
	return r.bridgeEngine(bridgeSession).ReadSSHFile(ctx, request)
}

func (r *Runtime) deploySSHBinaryForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.SSHBinaryDeploymentRequest) (runner.Result, error) {
	if err := r.waitForSSHTarget(ctx, request.Target); err != nil {
		if errors.Is(err, store.ErrTargetNotFound) {
			return r.missingTargetResult(ctx, bridgeSession, "ssh", request.Target, runner.StatusTargetNotFound)
		}
		if errors.Is(err, ErrTargetDisabled) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "target_disabled")
		}
		if errors.Is(err, ErrInvalidTargetInput) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", request.Target, runner.StatusRejected, "invalid_target")
		}
		return runner.Result{}, err
	}
	return r.bridgeEngine(bridgeSession).DeploySSHBinary(ctx, request)
}

func (r *Runtime) openSSHSessionForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.OpenSSHSessionRequest) (runner.SSHSessionResult, error) {
	if err := r.waitForSSHTarget(ctx, request.Target); err != nil {
		return r.sshSessionTargetFailure(ctx, bridgeSession, request.Target, err)
	}
	return r.bridgeEngine(bridgeSession).OpenSSHSession(ctx, request)
}

func (r *Runtime) setSSHSessionContextForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.SetSSHSessionContextRequest) (runner.SSHSessionResult, error) {
	return r.bridgeEngine(bridgeSession).SetSSHSessionContext(ctx, request)
}

func (r *Runtime) executeSSHSessionForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.ExecuteSSHSessionRequest) (runner.Result, error) {
	return r.bridgeEngine(bridgeSession).ExecuteSSHSession(ctx, request)
}

func (r *Runtime) closeSSHSessionForBridge(ctx context.Context, bridgeSession bridge.Session, sessionID string) (runner.SSHSessionResult, error) {
	return r.bridgeEngine(bridgeSession).CloseSSHSession(ctx, sessionID)
}

func (r *Runtime) runSQLForBridge(ctx context.Context, bridgeSession bridge.Session, request runner.SQLRequest) (runner.Result, error) {
	if err := r.waitForDatabaseTarget(ctx, request.Target); err != nil {
		if errors.Is(err, store.ErrTargetNotFound) {
			return r.missingTargetResult(ctx, bridgeSession, "database", request.Target, runner.StatusDatabaseNotFound)
		}
		if errors.Is(err, ErrTargetDisabled) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "database", request.Target, runner.StatusRejected, "target_disabled")
		}
		if errors.Is(err, ErrInvalidTargetInput) {
			return r.auditBridgeTargetDecision(ctx, bridgeSession, "database", request.Target, runner.StatusRejected, "invalid_target")
		}
		return runner.Result{}, err
	}
	engine := r.bridgeEngine(bridgeSession)
	return engine.RunSQL(ctx, request)
}

func (r *Runtime) waitForSSHTarget(ctx context.Context, target string) error {
	value, err := r.store.SSHTarget(ctx, target)
	if errors.Is(err, store.ErrInvalidTarget) {
		return fmt.Errorf("%w: %v", ErrInvalidTargetInput, err)
	}
	if errors.Is(err, store.ErrTargetNotFound) {
		return err
	}
	if err != nil {
		return err
	}
	if !value.Enabled {
		return ErrTargetDisabled
	}
	return nil
}

func (r *Runtime) waitForDatabaseTarget(ctx context.Context, target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%w: database target must use host:port: %v", ErrInvalidTargetInput, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: database port is invalid", ErrInvalidTargetInput)
	}
	value, err := r.store.DatabaseInstance(ctx, host, port)
	if errors.Is(err, store.ErrInvalidTarget) {
		return fmt.Errorf("%w: %v", ErrInvalidTargetInput, err)
	}
	if errors.Is(err, store.ErrTargetNotFound) {
		return err
	}
	if err != nil {
		return err
	}
	if !value.Enabled {
		return ErrTargetDisabled
	}
	return nil
}

func (r *Runtime) missingTargetResult(ctx context.Context, bridgeSession bridge.Session, targetKind, targetID, status string) (runner.Result, error) {
	result, err := r.auditBridgeTargetDecision(ctx, bridgeSession, targetKind, targetID, status, "target_not_found")
	if err != nil || result.Status == runner.StatusAuditWriteFailed {
		return result, err
	}
	if err := r.requestTUI(); err != nil {
		return runner.Result{}, err
	}
	return result, nil
}

func (r *Runtime) sshSessionTargetFailure(ctx context.Context, bridgeSession bridge.Session, targetID string, targetErr error) (runner.SSHSessionResult, error) {
	status, reason := runner.StatusRejected, "target_disabled"
	if errors.Is(targetErr, store.ErrTargetNotFound) {
		status, reason = runner.StatusTargetNotFound, "target_not_found"
	}
	if errors.Is(targetErr, ErrInvalidTargetInput) {
		reason = "invalid_target"
	}
	result, err := r.auditBridgeTargetDecision(ctx, bridgeSession, "ssh", targetID, status, reason)
	if err != nil {
		return runner.SSHSessionResult{}, err
	}
	if result.Status == runner.StatusAuditWriteFailed {
		return runner.SSHSessionResult{Status: runner.StatusAuditWriteFailed, Message: result.Message}, nil
	}
	if errors.Is(targetErr, store.ErrTargetNotFound) {
		if err := r.requestTUI(); err != nil {
			return runner.SSHSessionResult{}, err
		}
	}
	return runner.SSHSessionResult{Status: status, Message: result.Message, Decision: result.Decision, Reason: result.Reason}, nil
}

func (r *Runtime) auditBridgeTargetDecision(ctx context.Context, bridgeSession bridge.Session, targetKind, targetID, status, reason string) (runner.Result, error) {
	result := runner.Result{
		Status:           status,
		ExecutionOutcome: runner.StatusNotDispatched,
		AuditOutcome:     runner.AuditOutcomeRecorded,
		Message:          bridgeTargetMessage(targetKind, targetID, reason),
		Decision:         policy.DecisionRejected,
		Reason:           policy.ReasonInvalidRequest,
	}
	if r == nil || r.audit == nil {
		result.AuditOutcome = runner.AuditOutcomeFailed
		result.AuditWriteFailed = true
		return result, nil
	}
	if err := r.audit.Record(ctx, auditlog.Event{
		Time:   clock.Now(),
		Phase:  auditlog.PhaseDecision,
		Action: "target_lookup",
		Actor:  r.auditActor(bridgeSession),
		Target: auditlog.Target{Kind: targetKind, ID: targetID},
		Policy: auditlog.Policy{Version: policy.Version, Decision: string(policy.DecisionRejected), Reason: reason},
		Result: auditlog.Result{Status: status},
	}); err != nil {
		result.AuditOutcome = runner.AuditOutcomeFailed
		result.AuditWriteFailed = true
		return result, nil
	}
	return result, nil
}

func bridgeTargetMessage(targetKind, targetID, reason string) string {
	switch reason {
	case "target_not_found":
		return fmt.Sprintf("%s目标 %q 尚未登记，未连接远端。请在 ssh-mcp 本地控制台新增并验证该目标。", bridgeTargetKindName(targetKind), targetID)
	case "target_disabled":
		return fmt.Sprintf("%s目标 %q 已停用，未连接远端。请在 ssh-mcp 本地控制台启用并验证该目标。", bridgeTargetKindName(targetKind), targetID)
	case "invalid_target":
		if targetKind == "database" {
			return "数据库目标格式无效，必须使用“IP:端口”，例如 192.168.4.93:5432；未连接远端。"
		}
		return "SSH 目标格式无效，必须使用已登记的 IP 地址；未连接远端。"
	default:
		return runner.ResultMessage(runner.StatusRejected, "", policy.DecisionRejected, policy.ReasonInvalidRequest)
	}
}

func bridgeTargetKindName(targetKind string) string {
	if targetKind == "database" {
		return "数据库"
	}
	return "SSH"
}
