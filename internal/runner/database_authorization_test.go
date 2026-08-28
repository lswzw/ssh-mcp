package runner

import (
	"testing"
	"time"
)

func TestDatabaseTargetAuthorizerRevocationWaitsForStartedDispatch(t *testing.T) {
	t.Parallel()

	authorizer := NewDatabaseTargetAuthorizer()
	lease := authorizer.acquireTarget("192.0.2.20:5432")
	if lease == nil || !lease.BeginDispatch() {
		t.Fatal("无法开始数据库目标派发")
	}
	revoked := make(chan struct{})
	go func() {
		authorizer.RevokeTarget("192.0.2.20:5432")
		close(revoked)
	}()
	select {
	case <-revoked:
		t.Fatal("撤销在已开始的派发结束前返回")
	case <-time.After(20 * time.Millisecond):
	}
	lease.FinishDispatch()
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("派发结束后撤销没有返回")
	}
	authorizer.ActivateTarget("192.0.2.20:5432")
	if lease.BeginDispatch() {
		t.Fatal("旧数据库目标授权在重新开放后仍可派发")
	}
	replacement := authorizer.acquireTarget("192.0.2.20:5432")
	if replacement == nil || !replacement.BeginDispatch() {
		t.Fatal("重新开放后新的数据库目标授权无法派发")
	}
	replacement.FinishDispatch()
}
