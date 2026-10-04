package resource

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/slowdown"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/samber/lo"
)

type Parser[V any] func([]byte) (V, error)
type BundleFile func() (fs.File, error)

type FetcherOption[V any] func(*Fetcher[V])

// WithDiscard gives the fetcher ownership of successful parser results until
// publication. The callback disposes only the unpublished result, not values
// from earlier successful updates. A parser retains responsibility for partial
// results when it returns an error.
func WithDiscard[V any](discard func(V) error) FetcherOption[V] {
	return func(f *Fetcher[V]) { f.discard = discard }
}

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	name         string
	vehicle      P.Vehicle
	bundleFile   BundleFile
	updatedAt    time.Time
	hash         utils.HashType
	parser       Parser[V]
	interval     time.Duration
	onUpdate     func(V)
	discard      func(V) error
	loadBufMutex sync.Mutex
	stateMutex   sync.RWMutex
	startMutex   sync.Mutex
	started      bool
	backoff      slowdown.Backoff

	// lifecycleMutex protects admission and short commits, never downloads/parsers.
	lifecycleMutex sync.Mutex
	retired        bool
	active         int
	done           chan struct{}
	closeErr       error
	cleanupErr     error
}

func (f *Fetcher[V]) Name() string               { return f.name }
func (f *Fetcher[V]) Vehicle() P.Vehicle         { return f.vehicle }
func (f *Fetcher[V]) VehicleType() P.VehicleType { return f.vehicle.Type() }
func (f *Fetcher[V]) Context() context.Context   { return f.ctx }
func (f *Fetcher[V]) UpdatedAt() time.Time {
	f.stateMutex.RLock()
	defer f.stateMutex.RUnlock()
	return f.updatedAt
}

// Commit protects publication by this provider. Actions must be short and must
// not reenter Commit, Cancel or Wait; network work and parsing belong outside it.
func (f *Fetcher[V]) Commit(action func() error) error {
	f.lifecycleMutex.Lock()
	defer f.lifecycleMutex.Unlock()
	if f.retired {
		return context.Canceled
	}
	return action()
}

func (f *Fetcher[V]) begin() error {
	f.lifecycleMutex.Lock()
	defer f.lifecycleMutex.Unlock()
	if f.retired {
		return context.Canceled
	}
	f.active++
	return nil
}
func (f *Fetcher[V]) finish() {
	f.lifecycleMutex.Lock()
	defer f.lifecycleMutex.Unlock()
	f.active--
	if f.retired && f.active == 0 {
		close(f.done)
	}
}

// Cancel closes admission and invalidates future commits before returning.
// Work that ignores cancellation remains owned until Wait observes its exit.
func (f *Fetcher[V]) Cancel() {
	f.lifecycleMutex.Lock()
	defer f.lifecycleMutex.Unlock()
	if f.retired {
		return
	}
	f.retired = true
	f.ctxCancel()
	if f.active == 0 {
		close(f.done)
	}
}

// Wait waits for a canceled fetcher's requests and scheduler to finish. A
// deadline does not forget outstanding work; a later Wait can finish retirement.
func (f *Fetcher[V]) Wait(ctx context.Context) error {
	select {
	case <-f.done:
	default:
		select {
		case <-f.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.lifecycleMutex.Lock()
	closeErr, cleanupErr := f.closeErr, f.cleanupErr
	f.lifecycleMutex.Unlock()
	return errors.Join(closeErr, configresources.WaitCleanup(ctx, cleanupErr))
}
func (f *Fetcher[V]) Close() error {
	f.Cancel()
	return f.Wait(context.Background())
}
func (f *Fetcher[V]) recordCloseError(err error) {
	if err != nil {
		f.lifecycleMutex.Lock()
		f.closeErr = errors.Join(f.closeErr, err)
		f.lifecycleMutex.Unlock()
	}
}

// Failed candidate cleanup is a resource retirement condition, not an ordinary
// parse failure. Stop admitting updates and retain the actual close operation.
func (f *Fetcher[V]) recordCleanupError(err error) bool {
	var cleanup *configresources.CleanupError
	if !errors.As(err, &cleanup) {
		return false
	}
	f.lifecycleMutex.Lock()
	f.cleanupErr = errors.Join(f.cleanupErr, err)
	f.lifecycleMutex.Unlock()
	f.Cancel()
	return true
}

func (f *Fetcher[V]) Initial() (V, error) {
	if err := f.begin(); err != nil {
		return lo.Empty[V](), err
	}
	defer f.finish()
	if stat, err := os.Stat(f.vehicle.Path()); err == nil {
		if buf, err := os.ReadFile(f.vehicle.Path()); err == nil {
			contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), false)
			if err != nil && f.ctx.Err() != nil {
				return lo.Empty[V](), errors.Join(err, f.ctx.Err())
			}
			if err == nil {
				if err := f.setInitialTime(stat.ModTime()); err != nil {
					return lo.Empty[V](), err
				}
				if err := f.startPullLoop(time.Since(stat.ModTime()) > f.interval); err != nil {
					return lo.Empty[V](), err
				}
				return contents, nil
			}
		}
	}
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), err
	}

	if f.bundleFile != nil {
		if file, err := f.bundleFile(); err == nil {
			defer file.Close()
			buf, err := io.ReadAll(file)
			var modTime time.Time
			if stat, err := file.Stat(); err == nil {
				modTime = stat.ModTime()
			}
			var contents V
			if err == nil {
				contents, _, err = f.loadBuf(buf, utils.MakeHash(buf), true)
			}
			if err != nil && f.ctx.Err() != nil {
				return lo.Empty[V](), errors.Join(err, f.ctx.Err())
			}
			if err == nil {
				if err := f.setInitialTime(modTime); err != nil {
					return lo.Empty[V](), err
				}
				log.Infoln("[Provider] %s extract successful from bundle file", f.Name())
				if err := f.startPullLoop(time.Since(modTime) > f.interval); err != nil {
					return lo.Empty[V](), err
				}
				return contents, nil
			}
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), err)
		} else {
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), err)
		}
	}
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), err
	}
	contents, _, updateErr := f.update()
	// A failed read still starts the normal retry loop, unless retired.
	if err := f.startPullLoop(false); err != nil {
		return lo.Empty[V](), errors.Join(err, updateErr)
	}
	if updateErr != nil {
		return lo.Empty[V](), updateErr
	}
	return contents, nil
}
func (f *Fetcher[V]) setInitialTime(modTime time.Time) error {
	return f.Commit(func() error {
		f.stateMutex.Lock()
		f.updatedAt = modTime
		f.stateMutex.Unlock()
		return nil
	})
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	if err := f.begin(); err != nil {
		return lo.Empty[V](), false, err
	}
	defer f.finish()
	return f.update()
}
func (f *Fetcher[V]) update() (V, bool, error) {
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), false, err
	}
	f.stateMutex.RLock()
	oldHash := f.hash
	f.stateMutex.RUnlock()
	buf, hash, err := f.vehicle.Read(f.ctx, oldHash)
	if err != nil {
		_ = f.Commit(func() error { f.backoff.AddAttempt(); return nil })
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, hash, f.vehicle.Type() != P.File)
}
func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	if err := f.begin(); err != nil {
		return lo.Empty[V](), false, err
	}
	defer f.finish()
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), false, err
	}
	f.stateMutex.RLock()
	same := f.hash.Equal(hash)
	f.stateMutex.RUnlock()
	if same {
		err := f.Commit(func() error {
			now := time.Now()
			if updateFile {
				_ = os.Chtimes(f.vehicle.Path(), now, now)
			}
			f.stateMutex.Lock()
			f.updatedAt = now
			f.stateMutex.Unlock()
			f.backoff.Reset()
			return nil
		})
		return lo.Empty[V](), true, err
	}
	if buf == nil {
		return lo.Empty[V](), true, f.ctx.Err()
	}
	contents, err := f.parser(buf)
	if err != nil {
		f.recordCleanupError(err)
		_ = f.Commit(func() error { f.backoff.AddAttempt(); return nil })
		return lo.Empty[V](), false, err
	}
	err = f.Commit(func() error {
		if updateFile {
			if err := f.vehicle.Write(buf); err != nil {
				return err
			}
		}
		f.stateMutex.Lock()
		f.updatedAt = time.Now()
		f.hash = hash
		f.stateMutex.Unlock()
		f.backoff.Reset()
		if f.onUpdate != nil {
			f.onUpdate(contents)
		}
		return nil
	})
	if err != nil {
		if f.discard != nil {
			discardErr := f.discard(contents)
			if discardErr != nil && !f.recordCleanupError(discardErr) {
				f.recordCloseError(discardErr)
				f.Cancel()
			}
			err = errors.Join(err, discardErr)
		}
		return lo.Empty[V](), false, err
	}
	return contents, false, nil
}

func (f *Fetcher[V]) pullLoop(forceUpdate bool) {
	initialInterval := f.interval - time.Since(f.UpdatedAt())
	if initialInterval > f.interval {
		initialInterval = f.interval
	}
	if forceUpdate {
		log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
		f.updateWithLog()
	}
	if attempt := f.backoff.Attempt(); attempt > 0 {
		if duration := f.backoff.ForAttempt(attempt); duration < initialInterval {
			initialInterval = duration
		}
	}
	timer := time.NewTimer(initialInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			f.updateWithLog()
			interval := f.interval
			if attempt := f.backoff.Attempt(); attempt > 0 {
				if duration := f.backoff.ForAttempt(attempt); duration < interval {
					interval = duration
				}
			}
			timer.Reset(interval)
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) startPullLoop(forceUpdate bool) error {
	f.startMutex.Lock()
	defer f.startMutex.Unlock()
	if err := f.ctx.Err(); err != nil {
		return err
	}
	if f.started {
		return nil
	}
	if f.vehicle.Type() == P.File {
		if err := f.startWatcher(); err != nil {
			return err
		}
	} else if f.interval > 0 {
		if err := f.begin(); err != nil {
			return err
		}
		go func() { defer f.finish(); f.pullLoop(forceUpdate) }()
	}
	f.started = true
	return nil
}
func (f *Fetcher[V]) updateWithLog() {
	_, same, err := f.Update()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Errorln("[Provider] %s pull error: %s", f.Name(), err)
		}
		return
	}
	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}
	log.Infoln("[Provider] %s's content update", f.Name())
}

func NewFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser Parser[V], onUpdate func(V), options ...FetcherOption[V]) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	minBackoff := 10 * time.Second
	if interval < minBackoff {
		minBackoff = interval
	}
	f := &Fetcher[V]{
		ctxCancel: cancel, done: make(chan struct{}), name: name, bundleFile: bundleFile,
		vehicle: vehicle, parser: parser, onUpdate: onUpdate, interval: interval,
		backoff: slowdown.Backoff{Factor: 2, Jitter: false, Min: minBackoff, Max: interval},
	}
	for _, option := range options {
		option(f)
	}
	f.ctx = WithCommitGuard(ctx, f.Commit)
	return f
}
