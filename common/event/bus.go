// Package event provides synchronous, cancellable observations without owning
// background goroutines or queues.
package event

import (
	"sync"
	"sync/atomic"
)

// Bus is ready to use at its zero value and must not be copied after first use.
// Concurrent Emit calls may invoke the same callback concurrently. Callbacks
// must return promptly and must not panic; they may subscribe or cancel because
// no registry lock is held while calling them.
type Bus[T any] struct {
	mu          sync.Mutex
	subscribers map[*subscription[T]]struct{}
}

type subscription[T any] struct {
	active atomic.Bool
	fn     func(T)
}

// Subscribe returns an idempotent cancellation function. Cancellation excludes
// the subscriber from future emissions, but does not wait for callbacks already
// selected by concurrent emissions. Owners requiring shutdown barriers must
// reject stale events using their own lifetime/generation check. A nil callback
// creates no subscription.
func (b *Bus[T]) Subscribe(fn func(T)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	s := &subscription[T]{fn: fn}
	s.active.Store(true)
	b.mu.Lock()
	if b.subscribers == nil {
		b.subscribers = make(map[*subscription[T]]struct{})
	}
	b.subscribers[s] = struct{}{}
	b.mu.Unlock()
	return func() {
		if s.active.Swap(false) {
			b.mu.Lock()
			delete(b.subscribers, s)
			b.mu.Unlock()
		}
	}
}

// Emit notifies the current subscribers on the calling goroutine. Delivery
// order between different subscribers or concurrent emissions is unspecified.
func (b *Bus[T]) Emit(value T) {
	b.mu.Lock()
	snapshot := make([]*subscription[T], 0, len(b.subscribers))
	for s := range b.subscribers {
		snapshot = append(snapshot, s)
	}
	b.mu.Unlock()
	for _, s := range snapshot {
		if s.active.Load() {
			s.fn(value)
		}
	}
}
