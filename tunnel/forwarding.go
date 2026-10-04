package tunnel

import (
	"context"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"sync"
)

func EnableForwardingLifecycle() { forwarding.Enable() }
func StartForwarding(ctx context.Context, generation uint64) error {
	return forwarding.Start(ctx, generation)
}
func PrepareForwarding(ctx context.Context, generation uint64) error {
	return forwarding.Prepare(ctx, generation)
}
func ActivateForwarding(generation uint64) error { return forwarding.Activate(generation) }

type forwardingTunnel struct {
	tunnel
	ctx context.Context
}

func BoundForwardingTunnel(generation uint64) (C.Tunnel, error) {
	ctx, err := forwarding.Context(generation)
	if err != nil {
		return nil, err
	}
	return &forwardingTunnel{ctx: ctx}, nil
}
func (t *forwardingTunnel) BindContext(ctx context.Context) context.Context {
	return forwarding.Bind(ctx, t.ctx)
}
func (t *forwardingTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	metadata.RequestContext = t.BindContext(metadata.RequestContext)
	t.tunnel.HandleTCPConn(conn, metadata)
}
func (t *forwardingTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	metadata.RequestContext = t.BindContext(metadata.RequestContext)
	t.tunnel.HandleUDPPacket(packet, metadata)
}
func CancelForwarding()                        { forwarding.Cancel() }
func StopForwarding(ctx context.Context) error { return forwarding.Stop(ctx) }

func requestContext(metadata *C.Metadata) context.Context {
	if metadata.RequestContext != nil {
		return metadata.RequestContext
	}
	return context.Background()
}

type ownedPacket struct {
	C.UDPPacket
	finish func()
	once   sync.Once
}

func (p *ownedPacket) Drop() { p.once.Do(func() { p.UDPPacket.Drop(); p.finish() }) }
