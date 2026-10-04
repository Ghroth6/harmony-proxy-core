package adapter

import (
	"time"

	"github.com/metacubex/mihomo/common/event"
	C "github.com/metacubex/mihomo/constant"
)

// URLTestEvent describes a completed explicit or automatic health check. Proxy
// identifies the exact tested object, even when providers reuse a node name.
// Succeeded requires both a successful request and an accepted HTTP status.
// Delay is zero on failure; zero may also be a valid sub-millisecond success.
// Err preserves URLTest's error, so a rejected StatusCode can have a nil Err.
type URLTestEvent struct {
	Proxy        C.Proxy
	URL          string
	Name         string
	ProviderName string
	Time         time.Time
	Delay        uint16
	StatusCode   int
	Succeeded    bool
	Err          error
}

var urlTests event.Bus[URLTestEvent]

// SubscribeURLTests observes results after both general and per-URL histories
// have been updated. It does not change URLTest's existing return contract.
// Callbacks run synchronously, may run concurrently, and must return promptly.
// Cancellation is idempotent and does not wait for already selected callbacks.
func SubscribeURLTests(fn func(URLTestEvent)) (cancel func()) {
	return urlTests.Subscribe(fn)
}
