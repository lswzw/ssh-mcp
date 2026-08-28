package runner

import (
	"context"
	"sync"
)

// DispatchBarrier 在远端派发点建立全协议共享的锁定线性化边界。
type DispatchBarrier struct {
	mu       sync.Mutex
	locked   bool
	inFlight int
	drained  chan struct{}
}

// DispatchLease 是一次尚未或已经跨越远端派发点的资格。
type DispatchLease struct {
	barrier  *DispatchBarrier
	started  bool
	finished bool
}

func NewDispatchBarrier() *DispatchBarrier {
	return &DispatchBarrier{}
}

func (b *DispatchBarrier) Acquire() *DispatchLease {
	if b == nil {
		return &DispatchLease{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.locked {
		return nil
	}
	return &DispatchLease{barrier: b}
}

// BeginDispatch 只有在锁定边界前取得资格时返回 true。
func (l *DispatchLease) BeginDispatch() bool {
	if l == nil {
		return false
	}
	if l.barrier == nil {
		l.started = true
		return true
	}
	l.barrier.mu.Lock()
	defer l.barrier.mu.Unlock()
	if l.started || l.barrier.locked {
		return false
	}
	l.started = true
	if l.barrier.inFlight == 0 {
		l.barrier.drained = make(chan struct{})
	}
	l.barrier.inFlight++
	return true
}

func (l *DispatchLease) FinishDispatch() {
	if l == nil || !l.started || l.finished || l.barrier == nil {
		return
	}
	l.barrier.mu.Lock()
	if l.finished {
		l.barrier.mu.Unlock()
		return
	}
	l.finished = true
	if l.barrier.inFlight > 0 {
		l.barrier.inFlight--
	}
	var drained chan struct{}
	if l.barrier.inFlight == 0 {
		drained = l.barrier.drained
		l.barrier.drained = nil
	}
	l.barrier.mu.Unlock()
	if drained != nil {
		close(drained)
	}
}

// Lock 拒绝新的派发并等待已经跨越派发点的工作收束。
func (b *DispatchBarrier) Lock(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.locked = true
	drained := b.drained
	b.mu.Unlock()
	if drained == nil {
		return nil
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Block 立即封闭新派发资格，但不等待当前调用自身收束。
// 它用于本地安全状态无法持久化时的失败关闭路径。
func (b *DispatchBarrier) Block() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.locked = true
	b.mu.Unlock()
}

func (b *DispatchBarrier) Unlock() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.locked = false
	b.mu.Unlock()
}
