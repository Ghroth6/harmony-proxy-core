package proxydialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

type Tunnel interface {
	C.Tunnel
	ProxyLookup
}

// ProxyLookup is the exact dependency of named chained dialing. Embedded
// candidates can provide their own graph without borrowing a global tunnel.
type ProxyLookup interface {
	Proxies() map[string]C.Proxy
}

type byNameProxyDialer struct {
	proxyName string
	tunnel    C.Tunnel
	lookup    ProxyLookup
}

func (d byNameProxyDialer) proxies() (map[string]C.Proxy, error) {
	lookup := d.lookup
	if lookup == nil {
		lookup, _ = d.tunnel.(ProxyLookup)
	}
	if lookup == nil {
		return nil, fmt.Errorf("tunnel is invalid, must be proxydialer.Tunnel, but got: %T", d.tunnel)
	}
	return lookup.Proxies(), nil
}

func (d byNameProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	proxies, err := d.proxies()
	if err != nil {
		return nil, err
	}
	proxy, ok := proxies[d.proxyName]
	if !ok {
		return nil, fmt.Errorf("proxyName[%s] not found", d.proxyName)
	}
	return New(proxy, true).DialContext(ctx, network, address)
}

func (d byNameProxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	proxies, err := d.proxies()
	if err != nil {
		return nil, err
	}
	proxy, ok := proxies[d.proxyName]
	if !ok {
		return nil, fmt.Errorf("proxyName[%s] not found", d.proxyName)
	}
	return New(proxy, true).ListenPacket(ctx, network, address, rAddrPort)
}

func NewByName(proxyName string, tunnel C.Tunnel) C.Dialer {
	return byNameProxyDialer{proxyName: proxyName, tunnel: tunnel}
}

func NewByNameWithLookup(proxyName string, lookup ProxyLookup) C.Dialer {
	return byNameProxyDialer{proxyName: proxyName, lookup: lookup}
}
