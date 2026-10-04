package dialer

import (
	"context"
	"net"
	"sync/atomic"
)

// NetworkLifecycle is an optional embedded-platform boundary for physical
// outbound sockets. It is separate from socket protection itself: an existing
// socket must also be retired before the platform path changes.
type NetworkLifecycle struct {
	Acquire       func(context.Context) (context.Context, func(), error)
	OwnConn       func(context.Context, net.Conn) (net.Conn, error)
	OwnPacketConn func(context.Context, net.PacketConn) (net.PacketConn, error)
}

var networkLifecycle atomic.Pointer[NetworkLifecycle]

func SetNetworkLifecycle(lifecycle *NetworkLifecycle) { networkLifecycle.Store(lifecycle) }

func acquireNetwork(ctx context.Context) (context.Context, func(), *NetworkLifecycle, error) {
	lifecycle := networkLifecycle.Load()
	if lifecycle == nil {
		return ctx, func() {}, nil, nil
	}
	ctx, finish, err := lifecycle.Acquire(ctx)
	return ctx, finish, lifecycle, err
}
