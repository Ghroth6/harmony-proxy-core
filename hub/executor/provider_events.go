package executor

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/common/event"
	P "github.com/metacubex/mihomo/constant/provider"
)

// ProviderInitializationEvent is the result of one provider Initial call made
// by ApplyConfig. Generation identifies the serialized ApplyConfig attempt;
// it is not a provider update version or a claim of full configuration success.
// Update calls and background refreshes are deliberately outside this event.
type ProviderInitializationEvent struct {
	Name        string
	Type        P.ProviderType
	VehicleType P.VehicleType
	Generation  uint64
	Succeeded   bool
	Err         error
}

var providerInitializations event.Bus[ProviderInitializationEvent]
var configGeneration atomic.Uint64

// SubscribeProviderInitialization observes success and failure after Initial
// returns. ApplyConfig retains its upstream barrier: all initialization workers
// and these callbacks finish before it continues. Callbacks must return promptly
// and must not wait on ApplyConfig, directly or through an application lock.
// They may run concurrently. Cancellation is idempotent but does not wait for
// callbacks already selected by another goroutine.
func SubscribeProviderInitialization(fn func(ProviderInitializationEvent)) (cancel func()) {
	return providerInitializations.Subscribe(fn)
}
