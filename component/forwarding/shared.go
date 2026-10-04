package forwarding

import (
	"context"
	"net"
	"net/netip"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

// SharedDialContext is only for establishing a configuration-owned physical
// transport, never a request's logical stream. During establishment it retains
// the caller's cancellation (including deadline expiry), but not ownership. Call
// release when establishment returns: retained contexts (e.g. an inner tunnel)
// then belong to the pool, so a later caller cancellation cannot close the pool.
// The configuration owner remains responsible for closing the pooled transport.
// Deadline is deliberately absent throughout: the caller's deadline cancels the
// attempt through AfterFunc, without becoming a lifetime limit on the pool.
func SharedDialContext(caller context.Context) (context.Context, func()) {
	lifecycle.Lock()
	enabled := lifecycle.enabled
	lifecycle.Unlock()
	if !enabled {
		management.Lock()
		enabled = management.enabled
		management.Unlock()
	}
	if !enabled {
		return caller, func() {}
	}
	base := context.WithValue(context.WithoutCancel(caller), contextKey{}, (*run)(nil))
	ctx, cancel := context.WithCancelCause(base)
	var mu sync.Mutex
	released := false
	cancelAttempt := func() {
		mu.Lock()
		defer mu.Unlock()
		if !released {
			cancel(context.Cause(caller))
		}
	}
	stop := context.AfterFunc(caller, cancelAttempt)
	if caller.Err() != nil {
		cancelAttempt()
	}
	return ctx, func() {
		mu.Lock()
		if !released {
			if caller.Err() != nil {
				cancel(context.Cause(caller))
			}
			released = true
		}
		mu.Unlock()
		stop()
	}
}

type sharedDialer struct{ C.Dialer }

// SharedDialer adapts external pool implementations whose only physical-dial
// extension point is a C.Dialer. Ordinary proxydialer use retains its owner.
func SharedDialer(d C.Dialer) C.Dialer { return sharedDialer{d} }
func (d sharedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, release := SharedDialContext(ctx)
	defer release()
	return d.Dialer.DialContext(ctx, network, address)
}
func (d sharedDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	ctx, release := SharedDialContext(ctx)
	defer release()
	return d.Dialer.ListenPacket(ctx, network, address, remote)
}
