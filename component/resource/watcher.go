package resource

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/metacubex/mihomo/log"
)

// Own the debounce timer and loop directly: fswatch.Close does not join its
// delayed callbacks, so it cannot provide a provider retirement barrier.
func (f *Fetcher[V]) startWatcher() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	path := filepath.Clean(f.vehicle.Path())
	if err = w.Add(filepath.Dir(path)); err != nil {
		closeErr := w.Close()
		f.recordCloseError(closeErr)
		return errors.Join(err, closeErr)
	}
	if err = f.begin(); err != nil {
		closeErr := w.Close()
		f.recordCloseError(closeErr)
		return errors.Join(err, closeErr)
	}
	go func() {
		defer f.finish()
		defer func() { f.recordCloseError(w.Close()) }()
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		defer timer.Stop()
		var timerC <-chan time.Time
		for {
			select {
			case <-f.ctx.Done():
				return
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(event.Name) == path && event.Has(fsnotify.Create|fsnotify.Write) {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(100 * time.Millisecond)
					timerC = timer.C
				}
			case <-timerC:
				timerC = nil
				f.updateWithLog()
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Errorln("[Provider] %s watch error: %s", f.Name(), err)
			}
		}
	}()
	return nil
}
