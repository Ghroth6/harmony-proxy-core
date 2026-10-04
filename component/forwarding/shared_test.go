package forwarding

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSharedDialContextKeepsAttemptCancellation(t *testing.T) {
	resetLifecycle(t)
	Enable()
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := Start(parent, 1); err != nil {
		t.Fatal(err)
	}
	scope, finish, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	shared, release := SharedDialContext(scope)
	defer release()
	if Generation(shared) != 0 || Generation(scope) != 1 {
		t.Fatal("shared boundary altered root ownership")
	}
	if _, ok := shared.Deadline(); ok {
		t.Fatal("dial deadline became a pool lifetime limit")
	}
	Cancel()
	select {
	case <-shared.Done():
	case <-time.After(time.Second):
		t.Fatal("pending shared dial ignored cancellation")
	}
	if !errors.Is(shared.Err(), context.Canceled) {
		t.Fatal(shared.Err())
	}
}

func TestSharedDialContextExpiresPendingAttempt(t *testing.T) {
	resetLifecycle(t)
	Enable()
	caller, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	shared, release := SharedDialContext(caller)
	defer release()
	select {
	case <-shared.Done():
	case <-time.After(time.Second):
		t.Fatal("pending establishment ignored caller timeout")
	}
	if !errors.Is(context.Cause(shared), context.DeadlineExceeded) {
		t.Fatal(context.Cause(shared))
	}
}

func TestSharedDialCompletionDetachesRetainedContext(t *testing.T) {
	resetLifecycle(t)
	Enable()
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := Start(parent, 1); err != nil {
		t.Fatal(err)
	}
	scope, finish, err := Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	shared, release := SharedDialContext(scope)
	retained, releaseRetained := context.WithCancel(shared)
	defer releaseRetained()
	release()
	finish()
	if _, ok := shared.Deadline(); ok {
		t.Fatal("completed dial retained caller deadline")
	}
	cancel()
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := Stop(wait); err != nil {
		t.Fatal(err)
	}
	if err := retained.Err(); err != nil {
		t.Fatalf("completed shared transport canceled: %v", err)
	}
}
