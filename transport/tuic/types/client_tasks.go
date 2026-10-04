package types

import (
	"sync"
	"time"
)

// ClientTasks joins the client's protocol workers and cancels delayed stream
// accounting when the whole client is retired.
type ClientTasks struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	timers map[*time.Timer]struct{}
}

func (t *ClientTasks) Go(fn func()) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.wg.Add(1)
	go func() { defer t.wg.Done(); fn() }()
	return true
}

func (t *ClientTasks) After(delay time.Duration, fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if t.timers == nil {
		t.timers = make(map[*time.Timer]struct{})
	}
	t.wg.Add(1)
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		defer t.wg.Done()
		t.mu.Lock()
		delete(t.timers, timer)
		t.mu.Unlock()
		fn()
	})
	t.timers[timer] = struct{}{}
}

func (t *ClientTasks) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for timer := range t.timers {
		if timer.Stop() {
			t.wg.Done()
		}
	}
	t.timers = nil
}

func (t *ClientTasks) Wait() { t.wg.Wait() }
