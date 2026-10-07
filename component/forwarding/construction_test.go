package forwarding

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundCallerKeepsFixedScopeValuesAndBothCancellationSources(t *testing.T) {
	resetLifecycle(t)
	Enable()
	type scopeKey struct{}
	root := context.WithValue(context.Background(), scopeKey{}, "fixed-run-policy")
	if err := Start(root, 1); err != nil {
		t.Fatal(err)
	}
	scope, err := Context(1)
	if err != nil {
		t.Fatal(err)
	}
	caller, cancel := context.WithCancel(context.WithValue(context.Background(), scopeKey{}, "unmarked-caller"))
	bound := Bind(caller, scope)
	if bound.Value(scopeKey{}) != "fixed-run-policy" || Generation(bound) != 1 {
		t.Fatal("unmarked caller replaced the fixed run's policy values")
	}
	cancel()
	select {
	case <-bound.Done():
	case <-time.After(time.Second):
		t.Fatal("fixed binding ignored caller cancellation")
	}
	if _, _, err := Acquire(bound); err == nil {
		t.Fatal("cancelled bound caller was admitted")
	}
	alreadyCancelled := Bind(caller, scope)
	if alreadyCancelled.Err() == nil {
		t.Fatal("already cancelled parent was briefly admitted")
	}
	otherCaller, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()
	otherBound := Bind(otherCaller, scope)
	Cancel()
	select {
	case <-otherBound.Done():
	case <-time.After(time.Second):
		t.Fatal("caller binding ignored run cancellation")
	}
	ctx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	if err := Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

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
