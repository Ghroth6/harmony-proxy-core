package dialer

import (
	"context"
	"net"
	"net/netip"
)

// PacketDialer creates the actual packet socket, including any required
// platform protection and physical-socket lifecycle registration.
type PacketDialer interface {
	ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error)
}

// WithPacketDialer lets packet-based transports reuse normal address racing.
// The dialer creates the packet socket before calling handshake; the returned
// connection must close that socket when a losing candidate is discarded.
// This is deliberately separate from an opaque WithNetDialer callback.
func WithPacketDialer(packet PacketDialer, handshake func(context.Context, net.PacketConn, netip.AddrPort) (net.Conn, error)) Option {
	return WithNetDialer(packetNetDialer{packet: packet, handshake: handshake})
}

type packetNetDialer struct {
	packet    PacketDialer
	handshake func(context.Context, net.PacketConn, netip.AddrPort) (net.Conn, error)
}

func (d packetNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	remote, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	packet, err := d.packet.ListenPacket(ctx, network, "", remote)
	if err != nil {
		return nil, err
	}
	conn, err := d.handshake(ctx, packet, remote)
	if err != nil {
		_ = packet.Close()
	}
	return conn, err
}
