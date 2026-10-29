package resource

import (
	"context"
	"errors"
	"time"
)

// FetchResult is the latest completed attempt, not a content revision/history.
// Original errors continue to be logged by the caller; status exposes no URLs.
type FetchResult struct {
	At    time.Time
	State string
}

func (f *Fetcher[V]) LastResult() FetchResult {
	f.stateMutex.RLock()
	defer f.stateMutex.RUnlock()
	return f.lastResult
}
func (f *Fetcher[V]) recordResult(same bool, err error) {
	state := "updated"
	if same {
		state = "unchanged"
	}
	if err != nil {
		state = "failed"
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	f.stateMutex.Lock()
	f.lastResult = FetchResult{At: time.Now(), State: state}
	f.stateMutex.Unlock()
}
