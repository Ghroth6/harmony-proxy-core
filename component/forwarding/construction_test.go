package forwarding

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPreparedConstructionRetainsLateResourcesDuringStop(t *testing.T) {
	resetLifecycle(t)
	Enable()
	if err := Prepare(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	scope, _ := Context(1)
	if _, _, err := Acquire(scope); !errors.Is(err, ErrStopped) {
		t.Fatalf("prepared run admitted request: %v", err)
	}
	ctx, finish, err := AcquireConstruction(scope)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = Stop(stopCtx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop forgot unfinished constructor: %v", err)
	}
	if _, _, err := AcquireConstruction(scope); err == nil {
		t.Fatal("stopped run admitted constructor")
	}
	closed := make(chan struct{})
	Cleanup(ctx, func() error { close(closed); return nil })
	finish()
	stopCtx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("Stop completed before late constructor resource closed")
	}
	if err := Prepare(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}
