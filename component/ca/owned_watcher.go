package ca

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/metacubex/fswatch"
	"github.com/metacubex/tls"
)

// fswatch v0.1.1 does not expose its handle if adding a watch fails, and Close
// does not join deferred callbacks. This local owner uses the same fsnotify
// directory events and debounce, with complete failure/stop ownership.
type ownedKeyPairWatcher struct {
	paths   []string
	reload  func()
	get     func() (*tls.Certificate, error)
	watcher *fsnotify.Watcher
	done    chan struct{}
	once    sync.Once
	err     error
}

func (w *ownedKeyPairWatcher) Start() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w.watcher = watcher
	seen := map[string]bool{}
	for _, path := range w.paths {
		dir := filepath.Dir(path)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if err = watcher.Add(dir); err != nil {
			_ = watcher.Close()
			w.watcher = nil
			return err
		}
	}
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		var timer *time.Timer
		var tick <-chan time.Time
		defer func() {
			if timer != nil {
				timer.Stop()
			}
		}()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				for _, path := range w.paths {
					if event.Name != path {
						continue
					}
					if timer == nil {
						timer = time.NewTimer(fswatch.DefaultWaitTimeout)
					} else {
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						timer.Reset(fswatch.DefaultWaitTimeout)
					}
					tick = timer.C
				}
			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			case <-tick:
				tick = nil
				w.reload()
			}
		}
	}()
	return nil
}
func (w *ownedKeyPairWatcher) Close() error {
	w.once.Do(func() {
		if w.watcher != nil {
			w.err = w.watcher.Close()
			<-w.done
		}
	})
	return w.err
}
