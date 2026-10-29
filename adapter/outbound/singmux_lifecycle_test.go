package outbound_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	mux "github.com/metacubex/sing-mux"
	M "github.com/metacubex/sing/common/metadata"
)

type muxProbeConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *muxProbeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type muxProbeProxy struct {
	*outbound.Base
	address    string
	dials      atomic.Int32
	closeCalls atomic.Int32
	physical   *muxProbeConn
	closeErr   error
}

func (p *muxProbeProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, err
	}
	p.dials.Add(1)
	p.physical = &muxProbeConn{Conn: c, closed: make(chan struct{})}
	// Model the inner/platform path retaining the physical dial context.
	physical := p.physical
	stop := context.AfterFunc(ctx, func() { _ = physical.Close() })
	go func() { <-physical.closed; stop() }()
	return outbound.NewConn(physical, p), nil
}

func (p *muxProbeProxy) Close() error {
	p.closeCalls.Add(1)
	return p.closeErr
}

type muxEchoTunnel struct {
	C.Tunnel
	tcpDone chan struct{}
}

func (h *muxEchoTunnel) HandleTCPConn(c net.Conn, _ *C.Metadata) {
	defer func() { _ = c.Close(); h.tcpDone <- struct{}{} }()
	_, _ = io.Copy(c, c)
}

func (h *muxEchoTunnel) HandleUDPPacket(p C.UDPPacket, metadata *C.Metadata) {
	defer p.Drop()
	_, _ = p.WriteBack(p.Data(), metadata.UDPAddr())
}

func TestSingMuxSharedTransportAndOfficialClose(t *testing.T) {
	forwarding.Enable()
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		for _, padding := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/padding=%t", protocol, padding), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				serverCtx, stopServer := context.WithCancel(context.Background())
				defer stopServer()
				echo := &muxEchoTunnel{tcpDone: make(chan struct{}, 2)}
				handler, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: echo, Type: C.VLESS})
				if err != nil {
					t.Fatal(err)
				}
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = handler.NewConnection(serverCtx, conn, M.Metadata{Destination: mux.Destination})
				}()
				proxy := &muxProbeProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "mux-test", UDP: true}),
					address: listener.Addr().String(), closeErr: errors.New("underlying close result")}
				client, err := outbound.NewSingMux(outbound.SingMuxOption{Enabled: true, Protocol: protocol,
					Padding: padding, MaxConnections: 1}, proxy)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				request, cancel := context.WithCancel(context.Background())
				defer cancel()
				metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 1234}
				first, err := client.DialContext(request, metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				cancel()
				second, err := client.DialContext(context.Background(), metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				for _, conn := range []net.Conn{first, second} {
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					if _, err := conn.Write([]byte("tcp")); err != nil {
						t.Fatal(err)
					}
					var payload [3]byte
					if _, err := io.ReadFull(conn, payload[:]); err != nil {
						t.Fatal(err)
					}
					if string(payload[:]) != "tcp" {
						t.Fatal("TCP echo mismatch")
					}
				}
				udpMetadata := *metadata
				udpMetadata.NetWork = C.UDP
				udp, err := client.ListenPacketContext(context.Background(), &udpMetadata)
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				_ = udp.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := udp.WriteTo([]byte("udp"), udpMetadata.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				var payload [3]byte
				if _, _, err := udp.ReadFrom(payload[:]); err != nil {
					t.Fatal(err)
				}
				if string(payload[:]) != "udp" {
					t.Fatal("UDP echo mismatch")
				}
				if got := proxy.dials.Load(); got != 1 {
					t.Fatalf("physical dial count = %d, want 1", got)
				}
				if err := client.Close(); !errors.Is(err, proxy.closeErr) {
					t.Fatalf("underlying Close error lost: %v", err)
				}
				if got := proxy.closeCalls.Load(); got != 1 {
					t.Fatalf("underlying Close count = %d", got)
				}
				select {
				case <-proxy.physical.closed:
				case <-time.After(2 * time.Second):
					t.Fatal("official mux Close left physical transport open")
				}
				select {
				case <-serverDone:
				case <-time.After(2 * time.Second):
					t.Fatal("official server did not exit after transport closed")
				}
				for i := 0; i < 2; i++ {
					select {
					case <-echo.tcpDone:
					case <-time.After(2 * time.Second):
						t.Fatal("TCP echo callback did not exit")
					}
				}
			})
		}
	}
}
