package runner

import (
	"context"
	"testing"
	"time"
)

func TestTargetLanesSerializeWorkForTheSameTarget(t *testing.T) {
	t.Parallel()

	lanes := NewTargetLanes()
	firstRelease, err := lanes.Acquire(context.Background(), "ssh:192.0.2.10")
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	secondAcquired := make(chan func(), 1)
	secondError := make(chan error, 1)
	go func() {
		release, err := lanes.Acquire(context.Background(), "ssh:192.0.2.10")
		if err != nil {
			secondError <- err
			return
		}
		secondAcquired <- release
	}()

	select {
	case release := <-secondAcquired:
		release()
		t.Fatal("same-target work acquired the lane before its predecessor released it")
	case err := <-secondError:
		t.Fatalf("second Acquire() error = %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	firstRelease()
	select {
	case release := <-secondAcquired:
		release()
	case err := <-secondError:
		t.Fatalf("second Acquire() error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("same-target work did not acquire the lane after release")
	}
}

func TestTargetLanesAllowDifferentTargetsToProceedIndependently(t *testing.T) {
	t.Parallel()

	lanes := NewTargetLanes()
	firstRelease, err := lanes.Acquire(context.Background(), "database:192.0.2.20:5432")
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer firstRelease()

	secondRelease, err := lanes.Acquire(context.Background(), "database:192.0.2.21:5432")
	if err != nil {
		t.Fatalf("different target Acquire() error = %v", err)
	}
	secondRelease()
}

func TestTargetLanesShareReadsButDoNotLetThemPassQueuedWrite(t *testing.T) {
	t.Parallel()

	lanes := NewTargetLanes()
	firstReadRelease, err := lanes.AcquireRead(context.Background(), "database:192.0.2.20:5432")
	if err != nil {
		t.Fatalf("first AcquireRead() error = %v", err)
	}
	secondReadRelease, err := lanes.AcquireRead(context.Background(), "database:192.0.2.20:5432")
	if err != nil {
		t.Fatalf("second AcquireRead() error = %v", err)
	}

	writeAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := lanes.AcquireWrite(context.Background(), "database:192.0.2.20:5432")
		if acquireErr != nil {
			t.Errorf("AcquireWrite() error = %v", acquireErr)
			return
		}
		writeAcquired <- release
	}()
	select {
	case release := <-writeAcquired:
		release()
		t.Fatal("write acquired before active reads drained")
	case <-time.After(20 * time.Millisecond):
	}

	laterReadAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := lanes.AcquireRead(context.Background(), "database:192.0.2.20:5432")
		if acquireErr != nil {
			t.Errorf("later AcquireRead() error = %v", acquireErr)
			return
		}
		laterReadAcquired <- release
	}()
	firstReadRelease()
	secondReadRelease()
	var writeRelease func()
	select {
	case writeRelease = <-writeAcquired:
	case <-time.After(time.Second):
		t.Fatal("queued write did not acquire after readers released")
	}
	select {
	case release := <-laterReadAcquired:
		release()
		t.Fatal("later read passed queued write")
	case <-time.After(20 * time.Millisecond):
	}
	writeRelease()
	select {
	case release := <-laterReadAcquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("later read did not acquire after write released")
	}
}

func TestTargetLanesCanceledWaiterDoesNotBlockFollowingWork(t *testing.T) {
	t.Parallel()

	lanes := NewTargetLanes()
	release, err := lanes.AcquireWrite(context.Background(), "ssh:192.0.2.10")
	if err != nil {
		t.Fatalf("AcquireWrite() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, acquireErr := lanes.AcquireRead(canceled, "ssh:192.0.2.10")
		waiting <- acquireErr
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-waiting; err != context.Canceled {
		t.Fatalf("canceled AcquireRead() error = %v", err)
	}
	release()
	following, err := lanes.AcquireRead(context.Background(), "ssh:192.0.2.10")
	if err != nil {
		t.Fatalf("following AcquireRead() error = %v", err)
	}
	following()
}
