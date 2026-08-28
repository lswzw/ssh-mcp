package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var ErrInvalidTargetLane = errors.New("invalid target execution lane")

// TargetLanes 为每个目标提供公平的读写车道。
// 连续的只读请求可并行；审查后的写入独占目标，且不会被后来的读取插队。
type TargetLanes struct {
	mu    sync.Mutex
	lanes map[string]*targetLane
}

func NewTargetLanes() *TargetLanes {
	return &TargetLanes{lanes: make(map[string]*targetLane)}
}

type targetLane struct {
	readers int
	writer  bool
	queue   []*targetLaneRequest
}

type targetLaneRequest struct {
	write   bool
	ready   chan struct{}
	granted bool
}

// Acquire 保持对既有调用方的兼容，表示独占的写入车道。
func (m *TargetLanes) Acquire(ctx context.Context, target string) (func(), error) {
	return m.AcquireWrite(ctx, target)
}

// AcquireRead 取得可与其他已排队读取并行的只读车道。
func (m *TargetLanes) AcquireRead(ctx context.Context, target string) (func(), error) {
	return m.acquire(ctx, target, false)
}

// AcquireWrite 取得按到达顺序排队的独占写入车道。
func (m *TargetLanes) AcquireWrite(ctx context.Context, target string) (func(), error) {
	return m.acquire(ctx, target, true)
}

func (m *TargetLanes) acquire(ctx context.Context, target string, write bool) (func(), error) {
	if m == nil || strings.TrimSpace(target) == "" {
		return nil, ErrInvalidTargetLane
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	lane := m.lanes[target]
	if lane == nil {
		lane = &targetLane{}
		m.lanes[target] = lane
	}
	if len(lane.queue) == 0 && !lane.writer && (!write || lane.readers == 0) {
		if write {
			lane.writer = true
		} else {
			lane.readers++
		}
		m.mu.Unlock()
		return m.release(target, lane, write), nil
	}
	request := &targetLaneRequest{write: write, ready: make(chan struct{})}
	lane.queue = append(lane.queue, request)
	m.mu.Unlock()

	select {
	case <-request.ready:
		if err := ctx.Err(); err != nil {
			m.releaseGranted(target, lane, write)
			return nil, err
		}
		return m.release(target, lane, write), nil
	case <-ctx.Done():
		m.mu.Lock()
		if request.granted {
			m.mu.Unlock()
			m.releaseGranted(target, lane, write)
			return nil, ctx.Err()
		}
		m.removeRequestLocked(lane, request)
		m.grantLocked(lane)
		m.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (m *TargetLanes) release(target string, lane *targetLane, write bool) func() {
	var once sync.Once
	return func() {
		once.Do(func() { m.releaseGranted(target, lane, write) })
	}
}

func (m *TargetLanes) releaseGranted(target string, lane *targetLane, write bool) {
	if m == nil || lane == nil {
		return
	}
	m.mu.Lock()
	if write {
		lane.writer = false
	} else if lane.readers > 0 {
		lane.readers--
	}
	m.grantLocked(lane)
	if lane.readers == 0 && !lane.writer && len(lane.queue) == 0 && m.lanes[target] == lane {
		delete(m.lanes, target)
	}
	m.mu.Unlock()
}

func (m *TargetLanes) removeRequestLocked(lane *targetLane, request *targetLaneRequest) {
	for index, candidate := range lane.queue {
		if candidate != request {
			continue
		}
		copy(lane.queue[index:], lane.queue[index+1:])
		lane.queue[len(lane.queue)-1] = nil
		lane.queue = lane.queue[:len(lane.queue)-1]
		return
	}
}

func (m *TargetLanes) grantLocked(lane *targetLane) {
	if lane == nil || lane.writer || lane.readers > 0 || len(lane.queue) == 0 {
		return
	}
	first := lane.queue[0]
	if first.write {
		lane.queue = lane.queue[1:]
		first.granted = true
		lane.writer = true
		close(first.ready)
		return
	}
	for len(lane.queue) > 0 && !lane.queue[0].write {
		request := lane.queue[0]
		lane.queue = lane.queue[1:]
		request.granted = true
		lane.readers++
		close(request.ready)
	}
}
