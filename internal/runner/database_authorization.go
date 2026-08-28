package runner

import (
	"strings"
	"sync"
	"time"
)

// DatabaseTargetAuthorizer 将数据库目标的配置变更与远端派发线性化。
// 撤销先发生时，旧授权句柄不能派发；已经开始的派发会在撤销返回前结束。
type DatabaseTargetAuthorizer struct {
	mu      sync.Mutex
	targets map[string]*databaseTargetAuthorization
}

type databaseTargetAuthorization struct {
	generation   uint64
	blocked      bool
	dispatches   int
	dispatchDone chan struct{}
}

type databaseTargetLease struct {
	authorizer  *DatabaseTargetAuthorizer
	target      string
	targetAuth  *databaseTargetAuthorization
	generation  uint64
	dispatching bool
}

type databaseAuthorizationLease struct {
	managed bool
	lease   *databaseTargetLease
}

// NewDatabaseTargetAuthorizer 创建仅保存在进程内的数据库目标授权门禁。
func NewDatabaseTargetAuthorizer() *DatabaseTargetAuthorizer {
	return NewDatabaseTargetAuthorizerWithNow(time.Now)
}

// NewDatabaseTargetAuthorizerWithNow 保留调用兼容性；数据库目标授权不再维护审查计划状态。
func NewDatabaseTargetAuthorizerWithNow(_ func() time.Time) *DatabaseTargetAuthorizer {
	return &DatabaseTargetAuthorizer{
		targets: make(map[string]*databaseTargetAuthorization),
	}
}

// RevokeTarget 阻断目标的新派发，并等待已经取得派发权的请求结束。
func (a *DatabaseTargetAuthorizer) RevokeTarget(target string) {
	if a == nil || strings.TrimSpace(target) == "" {
		return
	}
	a.mu.Lock()
	targetAuth := a.targetLocked(target)
	targetAuth.generation++
	targetAuth.blocked = true
	dispatchDone := targetAuth.dispatchDone
	a.mu.Unlock()
	if dispatchDone != nil {
		<-dispatchDone
	}
}

// ActivateTarget 仅允许在撤销之后创建的新请求取得授权。
func (a *DatabaseTargetAuthorizer) ActivateTarget(target string) {
	if a == nil || strings.TrimSpace(target) == "" {
		return
	}
	a.mu.Lock()
	a.targetLocked(target).blocked = false
	a.mu.Unlock()
}

func (a *DatabaseTargetAuthorizer) acquireTarget(target string) *databaseTargetLease {
	if a == nil || strings.TrimSpace(target) == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	targetAuth := a.targetLocked(target)
	if targetAuth.blocked {
		return nil
	}
	return &databaseTargetLease{authorizer: a, target: target, targetAuth: targetAuth, generation: targetAuth.generation}
}

func (a *DatabaseTargetAuthorizer) targetLocked(target string) *databaseTargetAuthorization {
	targetAuth := a.targets[target]
	if targetAuth == nil {
		targetAuth = &databaseTargetAuthorization{generation: 1}
		a.targets[target] = targetAuth
	}
	return targetAuth
}

func (l *databaseTargetLease) BeginDispatch() bool {
	if l == nil || l.authorizer == nil {
		return false
	}
	l.authorizer.mu.Lock()
	defer l.authorizer.mu.Unlock()
	if l.dispatching || l.authorizer.targets[l.target] != l.targetAuth || l.targetAuth.blocked || l.targetAuth.generation != l.generation {
		return false
	}
	l.dispatching = true
	if l.targetAuth.dispatches == 0 {
		l.targetAuth.dispatchDone = make(chan struct{})
	}
	l.targetAuth.dispatches++
	return true
}

func (l *databaseTargetLease) FinishDispatch() {
	if l == nil || l.authorizer == nil {
		return
	}
	l.authorizer.mu.Lock()
	if !l.dispatching {
		l.authorizer.mu.Unlock()
		return
	}
	l.dispatching = false
	if l.targetAuth.dispatches > 0 {
		l.targetAuth.dispatches--
	}
	var dispatchDone chan struct{}
	if l.targetAuth.dispatches == 0 {
		dispatchDone = l.targetAuth.dispatchDone
		l.targetAuth.dispatchDone = nil
	}
	l.authorizer.mu.Unlock()
	if dispatchDone != nil {
		close(dispatchDone)
	}
}

func (l databaseAuthorizationLease) available() bool {
	return !l.managed || l.lease != nil
}

func (l databaseAuthorizationLease) beginDispatch() bool {
	return !l.managed || l.lease != nil && l.lease.BeginDispatch()
}

func (l databaseAuthorizationLease) finishDispatch() {
	if l.managed && l.lease != nil {
		l.lease.FinishDispatch()
	}
}
