package worksession

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultIdleTimeoutIsFiveMinutes(t *testing.T) {
	t.Parallel()

	if got, want := DefaultIdleTimeout, 5*time.Minute; got != want {
		t.Fatalf("DefaultIdleTimeout = %s, want %s", got, want)
	}
}

func TestValidateContextRejectsControlCharacterDirectory(t *testing.T) {
	t.Parallel()

	for _, directory := range []string{"/tmp\nnext", "/tmp\rnext"} {
		if err := ValidateContext(Context{WorkingDirectory: directory, Environment: map[string]string{}}); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("ValidateContext(%q) error = %v, want ErrInvalidContext", directory, err)
		}
	}
}

func TestStoreInvalidationBeforeDispatchPreventsDispatch(t *testing.T) {
	t.Parallel()

	store := New(Options{})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Release()

	store.ClearTarget(session.Target)
	if lease.BeginDispatch() {
		t.Fatal("BeginDispatch() = true after target invalidation, want false")
	}
}

func TestStoreOwnerBindsSessionAndRejectsOtherOwners(t *testing.T) {
	t.Parallel()

	store := New(Options{})
	owned, err := store.OpenForOwner("bridge-owner-a", "192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("OpenForOwner() 错误 = %v", err)
	}
	if owned.OwnerID != "bridge-owner-a" {
		t.Fatalf("OpenForOwner() 主体 = %q，期望 bridge-owner-a", owned.OwnerID)
	}
	other, err := store.OpenForOwner("bridge-owner-b", "192.0.2.21", 1, "policy-v1")
	if err != nil {
		t.Fatalf("OpenForOwner(other) 错误 = %v", err)
	}

	if _, err := store.AcquireForOwner("bridge-owner-b", owned.ID); !errors.Is(err, ErrSessionOwnerMismatch) {
		t.Fatalf("AcquireForOwner(其他主体) 错误 = %v，期望 ErrSessionOwnerMismatch", err)
	}
	if _, err := store.Acquire(owned.ID); !errors.Is(err, ErrSessionOwnerMismatch) {
		t.Fatalf("Acquire(兼容路径) 错误 = %v，期望 ErrSessionOwnerMismatch", err)
	}
	if _, err := store.CloseForOwner("bridge-owner-b", owned.ID); !errors.Is(err, ErrSessionOwnerMismatch) {
		t.Fatalf("CloseForOwner(其他主体) 错误 = %v，期望 ErrSessionOwnerMismatch", err)
	}

	lease, err := store.AcquireForOwner("bridge-owner-a", owned.ID)
	if err != nil {
		t.Fatalf("AcquireForOwner(主体) 错误 = %v", err)
	}
	if got := lease.Session().OwnerID; got != "bridge-owner-a" {
		t.Fatalf("Lease.Session().OwnerID = %q，期望 bridge-owner-a", got)
	}
	lease.Release()

	store.ClearOwner("bridge-owner-a")
	if _, err := store.AcquireForOwner("bridge-owner-a", owned.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("AcquireForOwner(已清理主体) 错误 = %v，期望 ErrSessionNotFound", err)
	}
	lease, err = store.AcquireForOwner("bridge-owner-b", other.ID)
	if err != nil {
		t.Fatalf("AcquireForOwner(保留主体) 错误 = %v", err)
	}
	lease.Release()
}

func TestStoreClearOwnerWaitsForClaimedDispatch(t *testing.T) {
	t.Parallel()

	store := New(Options{})
	owned, err := store.OpenForOwner("bridge-owner-a", "192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("OpenForOwner() 错误 = %v", err)
	}
	remaining, err := store.OpenForOwner("bridge-owner-b", "192.0.2.21", 1, "policy-v1")
	if err != nil {
		t.Fatalf("OpenForOwner(保留主体) 错误 = %v", err)
	}
	lease, err := store.AcquireForOwner("bridge-owner-a", owned.ID)
	if err != nil {
		t.Fatalf("AcquireForOwner() 错误 = %v", err)
	}
	defer lease.Release()
	if !lease.BeginDispatch() {
		t.Fatal("BeginDispatch() = false，期望 true")
	}

	cleared := make(chan struct{})
	go func() {
		store.ClearOwner("bridge-owner-a")
		close(cleared)
	}()
	select {
	case <-cleared:
		t.Fatal("ClearOwner() 在已领取派发完成前返回")
	case <-time.After(10 * time.Millisecond):
	}

	otherLease, err := store.AcquireForOwner("bridge-owner-b", remaining.ID)
	if err != nil {
		t.Fatalf("AcquireForOwner(保留主体) 错误 = %v", err)
	}
	otherLease.Release()
	lease.FinishDispatch()
	select {
	case <-cleared:
	case <-time.After(time.Second):
		t.Fatal("ClearOwner() 未在已领取派发完成后返回")
	}
	if _, err := store.AcquireForOwner("bridge-owner-a", owned.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("AcquireForOwner(已清理主体) 错误 = %v，期望 ErrSessionNotFound", err)
	}
}

func TestStoreCloseWaitsForClaimedDispatch(t *testing.T) {
	t.Parallel()

	store := New(Options{})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Release()
	if !lease.BeginDispatch() {
		t.Fatal("BeginDispatch() = false, want true")
	}

	closed := make(chan struct{})
	go func() {
		store.Close(session.ID)
		close(closed)
	}()

	deadline := time.After(time.Second)
	for {
		store.mu.Lock()
		invalidated := store.sessions[session.ID] == nil
		store.mu.Unlock()
		if invalidated {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Close() did not begin invalidating the session")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-closed:
		t.Fatal("Close() returned before the claimed dispatch finished")
	default:
	}

	lease.FinishDispatch()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close() did not return after the claimed dispatch finished")
	}
}

func TestStoreNotifiesAfterInvalidatingSession(t *testing.T) {
	t.Parallel()

	invalidated := make(chan Session, 1)
	store := New(Options{OnInvalidated: func(session Session) { invalidated <- session }})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Release()
	if !lease.BeginDispatch() {
		t.Fatal("BeginDispatch() = false, want true")
	}

	closed := make(chan struct{})
	go func() {
		store.Close(session.ID)
		close(closed)
	}()
	select {
	case got := <-invalidated:
		t.Fatalf("OnInvalidated() ran before dispatch ended: %#v", got)
	case <-time.After(10 * time.Millisecond):
	}

	lease.FinishDispatch()
	select {
	case got := <-invalidated:
		if got.ID != session.ID || got.Target != session.Target {
			t.Fatalf("OnInvalidated() = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("OnInvalidated() did not run after dispatch ended")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close() did not return")
	}
}

func TestStoreExpiredAcquireWaitsForClaimedDispatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	store := New(Options{IdleTimeout: time.Minute, Now: func() time.Time { return now }})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Release()
	if !lease.BeginDispatch() {
		t.Fatal("BeginDispatch() = false, want true")
	}
	now = now.Add(time.Minute)

	acquired := make(chan error, 1)
	go func() {
		_, err := store.Acquire(session.ID)
		acquired <- err
	}()

	deadline := time.After(time.Second)
	for {
		store.mu.Lock()
		expired := store.sessions[session.ID] == nil
		store.mu.Unlock()
		if expired {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Acquire() did not begin expiring the session")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-acquired:
		t.Fatalf("Acquire() returned %v before the claimed dispatch finished", err)
	default:
	}

	lease.FinishDispatch()
	select {
	case err := <-acquired:
		if err != ErrSessionExpired {
			t.Fatalf("Acquire() error = %v, want ErrSessionExpired", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Acquire() did not return after the claimed dispatch finished")
	}
}

func TestStoreConcurrentAcquireReportsTimerExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	secondAcquireReached := make(chan struct{})
	var nowCalls atomic.Int32
	store := New(Options{
		IdleTimeout: time.Hour,
		Now: func() time.Time {
			// 第四次读取时钟对应第二个 Acquire 在首次查找会话后的过期检查。
			if nowCalls.Add(1) == 4 {
				close(secondAcquireReached)
			}
			return now
		},
	})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer lease.Release()

	acquired := make(chan error, 1)
	go func() {
		_, err := store.Acquire(session.ID)
		acquired <- err
	}()
	select {
	case <-secondAcquireReached:
	case <-time.After(time.Second):
		t.Fatal("second Acquire() did not inspect the active session")
	}

	store.expire(session.ID, session.ExpiresAt)
	lease.Release()
	select {
	case err := <-acquired:
		if err != ErrSessionExpired {
			t.Fatalf("second Acquire() error = %v, want ErrSessionExpired", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Acquire() did not return after timer expiry")
	}
}

func TestStoreAcquireContextStopsWaitingForActiveLease(t *testing.T) {
	t.Parallel()

	store := New(Options{})
	session, err := store.Open("192.0.2.20", 1, "policy-v1")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	holder, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer holder.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := store.AcquireContext(ctx, session.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcquireContext() error = %v, want context deadline", err)
	}

	holder.Release()
	lease, err := store.Acquire(session.ID)
	if err != nil {
		t.Fatalf("Acquire() after canceled wait error = %v", err)
	}
	lease.Release()
}
