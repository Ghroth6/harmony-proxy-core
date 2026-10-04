package forwarding

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func resetLifecycle(t *testing.T) {
	t.Helper()
	lifecycle.Lock()
	lifecycle.enabled, lifecycle.current, lifecycle.last = false, nil, 0
	lifecycle.Unlock()
}

func TestForwardingOptInLeavesUnconfiguredUpstreamAdmission(t *testing.T) {
	resetLifecycle(t)
	ctx, finish, err := Acquire(nil)
	if err != nil || Generation(ctx) != 0 {
		t.Fatalf("default admission = %v, %v", ctx, err)
	}
	finish()
	Enable()
	if _, _, err := Acquire(nil); !errors.Is(err, ErrStopped) {
		t.Fatalf("opt-in initial admission = %v", err)
	}
	if _, finish, err := Acquire(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		finish()
	}
}

func TestForwardingCloseFailureRetainsObjectAndBlocksNextGeneration(t *testing.T) {
	resetLifecycle(t)
	Enable()
	if err := Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, finish, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("uncertain descriptor release")
	var closes atomic.Int32
	close := Cleanup(ctx, func() error { closes.Add(1); return closeErr })
	finish()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Stop(wait); !errors.Is(err, closeErr) {
		t.Fatalf("stop = %v", err)
	}
	if err := Start(context.Background(), 2); err == nil {
		t.Fatal("admitted after unknown cleanup")
	}
	if err := Stop(wait); !errors.Is(err, closeErr) {
		t.Fatalf("repeated stop forgot error: %v", err)
	}
	_ = close()
	if closes.Load() != 1 {
		t.Fatal("blindly retried Close")
	}
	r := current()
	r.mu.Lock()
	retained := len(r.resources)
	r.mu.Unlock()
	if retained != 1 {
		t.Fatalf("failed ownership retained = %d", retained)
	}
}

func TestForwardingWaitIncludesBlockingClose(t *testing.T) {
	resetLifecycle(t)
	Enable()
	if err := Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, finish, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	Cleanup(ctx, func() error { <-release; return nil })
	finish()
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := Stop(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocking close stop = %v", err)
	}
	cancel()
	if err := Start(context.Background(), 2); err == nil {
		t.Fatal("admitted during blocking Close")
	}
	close(release)
	wait, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Stop(wait); err != nil {
		t.Fatal(err)
	}
}
