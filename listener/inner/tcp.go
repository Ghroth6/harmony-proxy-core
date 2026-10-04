package inner

import (
	"context"
	"errors"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
)

var tunnel C.Tunnel

var ErrTunnelUninitialized = errors.New("tunnel uninitialized")

func New(t C.Tunnel) {
	tunnel = t
}

func GetTunnel() C.Tunnel {
	return tunnel
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string) (conn net.Conn, err error) {
	return HandleTcpContext(context.Background(), tunnel, address, proxy)
}

// HandleTcpContext marks an explicit internal root or inherits its forwarding
// owner. The caller's cancellation closes the pipe even before a dial returns.
func HandleTcpContext(ctx context.Context, tunnel C.Tunnel, address string, proxy string) (conn net.Conn, err error) {
	if scoped, ok := tunnel.(interface {
		BindContext(context.Context) context.Context
	}); ok {
		ctx = scoped.BindContext(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tunnel == nil {
		return nil, ErrTunnelUninitialized
	}

	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	if proxy != "" {
		metadata.SpecialProxy = proxy
	}
	if err = metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	ctx, finish, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	metadata.RequestContext = ctx
	conn1, conn2 := N.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = conn1.Close(); _ = conn2.Close() })
	go func() { defer finish(); defer cancel(); defer stop(); tunnel.HandleTCPConn(conn2, metadata) }()
	return &innerTCPConn{Conn: conn1, cancel: cancel}, nil
}

type innerTCPConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *innerTCPConn) Close() error { c.cancel(); return c.Conn.Close() }
