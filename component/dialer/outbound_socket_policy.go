package dialer

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
)

// OutboundSocketPolicy is installed once before mobile operations begin.
// Required distinguishes explicitly owned forwarding from independent work.
// Control runs in the real net.Dialer RawConn validity interval before connect.
type OutboundSocketPolicy struct {
	Required func(context.Context) bool
	Control  func(context.Context, string, string, syscall.RawConn) error
}

var outboundSocketPolicy atomic.Pointer[OutboundSocketPolicy]

var ErrUnsupportedSocketPolicyDialer = errors.New("custom dialer cannot enforce required socket policy")

func InstallOutboundSocketPolicy(policy OutboundSocketPolicy) error {
	if policy.Required == nil || policy.Control == nil {
		return errors.New("invalid outbound socket policy")
	}
	if !outboundSocketPolicy.CompareAndSwap(nil, &policy) {
		return errors.New("outbound socket policy already installed")
	}
	return nil
}
