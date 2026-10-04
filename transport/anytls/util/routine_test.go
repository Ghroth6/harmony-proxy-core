package util

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRoutineCancelInterruptsTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var called atomic.Bool
	done := StartRoutine(ctx, time.Hour, func() { called.Store(true) })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt sleeping timer")
	}
	if called.Load() {
		t.Fatal("cancelled timer ran its callback")
	}
}

func TestRoutineCompletionIncludesRunningCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	done := StartRoutine(ctx, time.Millisecond, func() {
		close(started)
		<-release
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("callback did not start")
	}
	cancel()
	select {
	case <-done:
		close(release)
		t.Fatal("completion preceded callback return")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback return did not finish cancelled routine")
	}
}
