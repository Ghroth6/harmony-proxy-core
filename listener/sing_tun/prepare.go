package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var connectICMPDestination = ping.ConnectDestination

type forwardingDestination struct {
	tun.DirectRouteDestination
	ctx   context.Context
	close func() error
}

func (d *forwardingDestination) Close() error { return d.close() }
func (d *forwardingDestination) IsClosed() bool {
	return d.ctx.Err() != nil || d.DirectRouteDestination.IsClosed()
}
func (d *forwardingDestination) WritePacket(packet *buf.Buffer) error {
	_, finish, err := forwarding.Acquire(d.ctx)
	if err != nil {
		return err
	}
	defer finish()
	return d.DirectRouteDestination.WritePacket(packet)
}

type forwardingRouteContext struct {
	tun.DirectRouteContext
	ctx context.Context
}

func (r *forwardingRouteContext) WritePacket(packet []byte) error {
	_, finish, err := forwarding.Acquire(r.ctx)
	if err != nil {
		return err
	}
	defer finish()
	return r.DirectRouteContext.WritePacket(packet)
}

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		ctx, finish, err := h.acquireForwarding(context.Background())
		if err != nil {
			return nil, err
		}
		defer finish()
		if h.DisableICMPForwarding || h.skipPingForwardingByAddr(destination.Addr) { // skip if ICMP handling is disabled or other condition
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
		}
		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := connectICMPDestination(ctx, log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, &forwardingRouteContext{routeContext, ctx}, timeout)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		owned := &forwardingDestination{DirectRouteDestination: directRouteDestination, ctx: ctx, close: forwarding.Cleanup(ctx, directRouteDestination.Close)}
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, owned.Close())
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return owned, nil
	}
	return nil, nil
}

func (h *ListenerHandler) skipPingForwardingByAddr(addr netip.Addr) bool {
	for _, prefix := range h.Inet4Address { // skip in interface ipv4 range
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address { // skip in interface ipv6 range
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) { // skip in fakeIp pool
		return true
	}
	return false
}
