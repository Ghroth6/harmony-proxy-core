package ntp

import (
	"context"
	"testing"
	"time"
)

func TestUnrepresentableOwnedIntervalCanRetireWithoutStartingWorker(t *testing.T) {
	for _, interval := range []time.Duration{0, -1, time.Duration(1<<63 - 1)} {
		owner := NewOwnedService("127.0.0.1:123", interval, nil, false)
		if err := owner.Activate(context.Background()); err == nil {
			t.Fatal("unrepresentable ticker started")
		}
		owner.Cancel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := owner.Wait(ctx); err != nil {
			t.Fatal("failed activation left a nonexistent worker pending", err)
		}
		cancel()
	}
}
