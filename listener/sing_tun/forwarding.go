package sing_tun

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/forwarding"
)

// DNS hijacking and direct ICMP do not pass through Tunnel.Handle*; acquire the
// same frozen owner explicitly. Unmanaged callers retain their own context.
func (h *ListenerHandler) acquireForwarding(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if bound, ok := h.Tunnel.(interface {
		BindContext(context.Context) context.Context
	}); ok {
		ctx = bound.BindContext(ctx)
	}
	return forwarding.Acquire(ctx)
}

// RelayDnsConn may translate resolver cancellation to SERVFAIL. Do not publish
// that response after this TUN generation was cancelled.
type dnsReplyConn struct {
	net.Conn
	ctx context.Context
}

func (c *dnsReplyConn) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
