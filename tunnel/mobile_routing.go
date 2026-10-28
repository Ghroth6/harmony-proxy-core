package tunnel

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/mobile/protection"
)

var (
	ErrMobilePolicyContextInvalid = errors.New("MOBILE_POLICY_CONTEXT_INVALID")
)

type mobilePolicyRoutingKey struct{}
type mobilePolicyRun struct{ generation uint64 }

// WithMobilePolicyRouting is a pure value marker for one accepted original
// policy run. Runtime applies it to the protected root before forwarding
// preparation. Shared DNS may detach a waiter's forwarding owner, but retains
// this fixed policy/protection generation and its own real worker lifecycle.
func WithMobilePolicyRouting(ctx context.Context) context.Context {
	return context.WithValue(ctx, mobilePolicyRoutingKey{}, mobilePolicyRun{generation: protection.Generation(ctx)})
}

func mobilePolicyRouting(ctx context.Context) (bool, error) {
	owner, marked := ctx.Value(mobilePolicyRoutingKey{}).(mobilePolicyRun)
	if !marked {
		return false, nil
	}
	if owner.generation == 0 || protection.Generation(ctx) != owner.generation {
		return true, ErrMobilePolicyContextInvalid
	}
	if generation := forwarding.Generation(ctx); generation != 0 && generation != owner.generation {
		return true, ErrMobilePolicyContextInvalid
	}
	return true, nil
}
