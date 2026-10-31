package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

type packetPolicyKey struct{}

func installPacketTestPolicy(t *testing.T, control func(context.Context, string, string, syscall.RawConn) error) {
	t.Helper()
	old := outboundSocketPolicy.Load()
	outboundSocketPolicy.Store(&OutboundSocketPolicy{
		Required: func(ctx context.Context) bool { return ctx.Value(packetPolicyKey{}) == true },
		Control:  control,
	})
	t.Cleanup(func() { outboundSocketPolicy.Store(old) })
}

func TestPacketDialerProtectsPhysicalSocketWithoutWrappingProtocolResult(t *testing.T) {
	var controls, packets, streams atomic.Int32
	installPacketTestPolicy(t, func(ctx context.Context, _, _ string, raw syscall.RawConn) error {
		if ctx.Value(packetPolicyKey{}) != true {
			t.Error("protection marker lost")
		}
		return raw.Control(func(uintptr) { controls.Add(1) })
	})
	old := networkLifecycle.Load()
	SetNetworkLifecycle(&NetworkLifecycle{
		Acquire: func(ctx context.Context) (context.Context, func(), error) { return ctx, func() {}, nil },
		OwnConn: func(_ context.Context, conn net.Conn) (net.Conn, error) {
			streams.Add(1)
			return &struct{ net.Conn }{conn}, nil
		},
		OwnPacketConn: func(_ context.Context, conn net.PacketConn) (net.PacketConn, error) {
			packets.Add(1)
			return conn, nil
		},
	})
	t.Cleanup(func() { SetNetworkLifecycle(old) })
	var protocol *packetTestConn
	d := NewDialer(WithPacketDialer(NewDialer(), func(_ context.Context, packet net.PacketConn, _ netip.AddrPort) (net.Conn, error) {
		protocol = &packetTestConn{packet: packet}
		return protocol, nil
	}))
	ctx := context.WithValue(context.Background(), packetPolicyKey{}, true)
	conn, err := d.DialContext(ctx, "udp4", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn != protocol || controls.Load() != 1 || packets.Load() != 1 || streams.Load() != 0 {
		t.Fatalf("protocol=%T identity=%v controls=%d packets=%d stream wrappers=%d", conn, conn == protocol, controls.Load(), packets.Load(), streams.Load())
	}
}

func TestPacketDialerDoesNotExemptOpaqueNetDialer(t *testing.T) {
	installPacketTestPolicy(t, func(context.Context, string, string, syscall.RawConn) error { return nil })
	called := false
	d := NewDialer(WithNetDialer(NetDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	})))
	ctx := context.WithValue(context.Background(), packetPolicyKey{}, true)
	_, err := d.DialContext(ctx, "udp4", "127.0.0.1:443")
	if !errors.Is(err, ErrUnsupportedSocketPolicyDialer) || called {
		t.Fatalf("opaque callback called=%v error=%v", called, err)
	}
}

func TestPacketDialerClosesSocketOnHandshakeFailure(t *testing.T) {
	packet := newPacketTestSocket()
	want := errors.New("handshake failed")
	d := NewDialer(WithPacketDialer(packetTestDialer(func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
		return packet, nil
	}), func(context.Context, net.PacketConn, netip.AddrPort) (net.Conn, error) { return nil, want }))
	_, err := d.DialContext(context.Background(), "udp4", "127.0.0.1:443")
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("failed handshake retained packet socket")
	}
}

func TestPacketDialerReusesConcurrentRacingAndClosesLateWinner(t *testing.T) {
	previous := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previous) })
	firstIP := netip.MustParseAddr("192.0.2.1")
	secondIP := netip.MustParseAddr("192.0.2.2")
	firstStarted, releaseFirst := make(chan struct{}), make(chan struct{})
	firstPacket, secondPacket := newPacketTestSocket(), newPacketTestSocket()
	var release sync.Once
	defer release.Do(func() { close(releaseFirst) })
	packetDialer := packetTestDialer(func(_ context.Context, _, _ string, remote netip.AddrPort) (net.PacketConn, error) {
		if remote.Addr() == firstIP {
			return firstPacket, nil
		}
		return secondPacket, nil
	})
	d := NewDialer(WithResolver(packetTestResolver{ips: []netip.Addr{firstIP, secondIP}}), WithPacketDialer(packetDialer,
		func(ctx context.Context, packet net.PacketConn, remote netip.AddrPort) (net.Conn, error) {
			if remote.Addr() == firstIP {
				close(firstStarted)
				select {
				case <-releaseFirst:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			} else {
				select {
				case <-firstStarted:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return &packetTestConn{packet: packet}, nil
		}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "udp4", "packet-race.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.(*packetTestConn).packet != secondPacket {
		t.Fatal("blocked first address prevented second address from winning")
	}
	release.Do(func() { close(releaseFirst) })
	select {
	case <-firstPacket.closed:
	case <-ctx.Done():
		t.Fatal("late successful candidate was not closed")
	}
}

type packetTestDialer func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error)

func (d packetTestDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	return d(ctx, network, address, remote)
}

type packetTestSocket struct {
	net.PacketConn
	once   sync.Once
	closed chan struct{}
}

func newPacketTestSocket() *packetTestSocket { return &packetTestSocket{closed: make(chan struct{})} }
func (p *packetTestSocket) Close() error     { p.once.Do(func() { close(p.closed) }); return nil }

type packetTestConn struct {
	net.Conn
	packet net.PacketConn
}

func (c *packetTestConn) Close() error { return c.packet.Close() }

type packetTestResolver struct {
	resolver.Resolver
	ips []netip.Addr
}

func (r packetTestResolver) Invalid() bool { return true }
func (r packetTestResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func (r packetTestResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func (r packetTestResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}
