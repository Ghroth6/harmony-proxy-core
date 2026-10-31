package resource

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/utils"
	"time"
)

// InitialPrepared loads caller-verified bytes without publishing callbacks or
// starting I/O. Activation later uses the same upstream cache/watch scheduler.
func (f *Fetcher[V]) InitialPrepared(input []byte, modified time.Time) (V, error) {
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
	value, err := f.parser(input)
	if err != nil {
		return empty, err
	}
	f.prepared = true
	f.stateMutex.Lock()
	f.hash, f.updatedAt = utils.MakeHash(input), modified
	f.stateMutex.Unlock()
	return value, nil
}

// ActivateScheduled defers acquisition until the runtime owns the network.
// Existing bytes retain their age; absent bytes use upstream cache, bundle,
// fallback and initial acquisition. File sources use the normal file watcher.
func (f *Fetcher[V]) ActivateScheduled(root context.Context) error {
	f.startMutex.Lock()
	if root == nil || root.Err() != nil {
		f.startMutex.Unlock()
		return context.Canceled
	}
	if f.started {
		f.startMutex.Unlock()
		return nil
	}
	prepared := f.prepared
	if !prepared {
		f.startMutex.Unlock()
		if err := f.BindContext(root); err != nil {
			return err
		}
		_, err := f.Initial()
		return err
	}
	f.lifecycleMutex.Lock()
	if f.retired {
		f.lifecycleMutex.Unlock()
		f.startMutex.Unlock()
		return context.Canceled
	}
	f.ctxCancel()
	ctx, cancel := context.WithCancel(root)
	f.ctx, f.ctxCancel = WithCommitGuard(ctx, f.Commit), cancel
	f.networkRoot = f.ctx
	f.lifecycleMutex.Unlock()
	f.startMutex.Unlock()
	return f.startPullLoop(time.Since(f.UpdatedAt()) > f.interval)
}
