package resource

import (
	"context"
	"errors"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

// InitialPrepared parses exactly the caller's verified immutable bytes. It
// never reads the original path or starts a watcher, request or scheduler.
func (f *Fetcher[V]) InitialPrepared(input []byte) (V, error) {
	f.startMutex.Lock()
	defer f.startMutex.Unlock()
	var empty V
	if f.started || f.prepared {
		return empty, errors.New("prepared resource already initialized")
	}
	if err := f.begin(); err != nil {
		return empty, err
	}
	defer f.finish()
	f.prepared = true
	value, _, err := f.loadBuf(input, utils.MakeHash(input), false)
	return value, err
}

// ActivateScheduled is the sole prepared provider scheduler. Its first tick
// starts a full configured interval after explicit activation, independent of
// old file mtime. The fixed run root retains protection and network ownership.
func (f *Fetcher[V]) ActivateScheduled(root context.Context) error {
	f.startMutex.Lock()
	defer f.startMutex.Unlock()
	if !f.prepared || root == nil || root.Err() != nil {
		return errors.New("prepared resource cannot activate")
	}
	if f.started {
		return nil
	}
	f.lifecycleMutex.Lock()
	if f.retired {
		f.lifecycleMutex.Unlock()
		return context.Canceled
	}
	ctx, cancel := context.WithCancel(root)
	f.networkRoot = WithCommitGuard(ctx, f.Commit)
	f.networkCancel = cancel
	f.started = true
	scheduled := f.vehicle.Type() == P.HTTP && f.interval > 0
	if scheduled {
		f.active++
	}
	f.lifecycleMutex.Unlock()
	if scheduled {
		go func() { defer f.finish(); f.preparedPullLoop(ctx) }()
	}
	return nil
}

func (f *Fetcher[V]) preparedPullLoop(ctx context.Context) {
	timer := time.NewTimer(f.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.ctx.Done():
			return
		case <-timer.C:
			f.updateWithLog()
			timer.Reset(f.interval)
		}
	}
}
