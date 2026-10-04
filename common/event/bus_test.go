package event

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSynchronousDeliveryAndSelfCancellation(t *testing.T) {
	var bus Bus[int]
	var seen []int
	var cancel func()
	cancel = bus.Subscribe(func(value int) {
		seen = append(seen, value)
		cancel()
		// Callback code can also register without reentering a held lock.
		bus.Subscribe(func(next int) { seen = append(seen, next*10) })
	})
	bus.Emit(1)
	if len(seen) != 1 || seen[0] != 1 {
		t.Fatalf("delivery must finish inline and exclude new subscriptions: %v", seen)
	}
	cancel()
	bus.Emit(2)
	if len(seen) != 2 || seen[1] != 20 {
		t.Fatalf("cancelled subscriber received a new event: %v", seen)
	}
	bus.Subscribe(nil)()
}

func TestCancellationDoesNotWaitForInflightCallback(t *testing.T) {
	var bus Bus[int]
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var count atomic.Int64
	cancel := bus.Subscribe(func(int) {
		count.Add(1)
		close(entered)
		<-release
	})
	go func() { bus.Emit(1); close(done) }()
	<-entered
	cancel()
	bus.Emit(2)
	if count.Load() != 1 {
		t.Fatal("emission started after cancel invoked the old subscriber")
	}
	close(release)
	<-done
}

func TestConcurrentPublicationAndSubscription(t *testing.T) {
	var bus Bus[int]
	var count atomic.Int64
	cancel := bus.Subscribe(func(int) { count.Add(1) })
	const workers, events = 16, 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < events; j++ {
				stop := bus.Subscribe(func(int) {})
				bus.Emit(j)
				stop()
				stop()
			}
		}()
	}
	wg.Wait()
	cancel()
	bus.Emit(0)
	if count.Load() != workers*events {
		t.Fatalf("stable subscriber missed or duplicated events: %d", count.Load())
	}
}
