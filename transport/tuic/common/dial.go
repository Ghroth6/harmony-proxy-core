package common

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/dialer"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type PacketDialer interface {
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

type DialQuicOption struct {
	Early              bool
	ConnectionIDLength int
}

func DialQuic(ctx context.Context, address string, opts []dialer.Option, pDialer PacketDialer, tlsConf *tls.Config, conf *quic.Config, option DialQuicOption) (net.PacketConn, *quic.Conn, error) {
	addresses, err := dialer.ResolveUDPAddresses(ctx, address, opts...)
	if err != nil {
		return nil, nil, err
	}
	var failures []error
	for _, remote := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		packet, err := pDialer.ListenPacket(ctx, "udp", "", remote)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		transport := quic.Transport{Conn: packet, ConnectionIDLength: option.ConnectionIDLength}
		transport.SetCreatedConn(true)
		transport.SetSingleUse(true)
		var connection *quic.Conn
		if option.Early {
			connection, err = transport.DialEarly(ctx, net.UDPAddrFromAddrPort(remote), tlsConf, conf)
		} else {
			connection, err = transport.Dial(ctx, net.UDPAddrFromAddrPort(remote), tlsConf, conf)
		}
		if err == nil {
			return packet, connection, nil
		}
		_ = transport.Close()
		_ = packet.Close()
		failures = append(failures, err)
	}
	return nil, nil, errors.Join(failures...)
}
