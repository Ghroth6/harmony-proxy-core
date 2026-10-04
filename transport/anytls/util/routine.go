package util

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/metacubex/mihomo/log"
)

// StartRoutine returns a completion signal so an owner can cancel and join its
// timer, including a callback already in progress.
func StartRoutine(ctx context.Context, d time.Duration, f func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
			}
		}()
		timer := time.NewTimer(d)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				return
			}
			f()
			timer.Reset(d)
		}
	}()
	return done
}
