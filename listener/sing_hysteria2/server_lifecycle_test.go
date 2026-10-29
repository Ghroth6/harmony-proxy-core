package sing_hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type lifecycleTunnel struct{ ctx context.Context }

func (t lifecycleTunnel) BindContext(ctx context.Context) context.Context {
	return forwarding.Bind(ctx, t.ctx)
}

type echoTunnel struct{ lifecycleTunnel }

func (echoTunnel) HandleTCPConn(c net.Conn, _ *C.Metadata) {
	defer c.Close()
	_, _ = io.Copy(c, c)
}
func (echoTunnel) HandleUDPPacket(p C.UDPPacket, metadata *C.Metadata) {
	defer p.Drop()
	_, _ = p.WriteBack(p.Data(), &net.UDPAddr{IP: net.IP(metadata.DstIP.AsSlice()), Port: int(metadata.DstPort)})
}

type observedDialer struct {
	C.Dialer
	packets []net.PacketConn
}

func (d *observedDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	p, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err == nil {
		d.packets = append(d.packets, p)
		// Model a platform/inner transport retaining its dial context.
		context.AfterFunc(ctx, func() { _ = p.Close() })
	}
	return p, err
}

func TestHysteria2ClientReusesConnectionAfterRequestCancellation(t *testing.T) {
	forwarding.Enable()
	for _, obfs := range []string{"", "salamander", "gecko"} {
		t.Run("obfs="+obfs, func(t *testing.T) {
			cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(LC.Hysteria2Server{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key,
				Users: map[string]string{"test": "password"}, Obfs: obfs, ObfsPassword: "obfuscation"},
				&net.ListenConfig{}, echoTunnel{lifecycleTunnel{context.Background()}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			addr := server.AddrList()[0].(*net.UDPAddr)
			dialer := &observedDialer{}
			client, err := outbound.NewHysteria2(outbound.Hysteria2Option{
				BasicOption: outbound.BasicOption{DialerForAPI: dialer}, Name: "loopback",
				Server: "127.0.0.1", Port: addr.Port, Password: "password", SkipCertVerify: true,
				Obfs: obfs, ObfsPassword: "obfuscation"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 1234}
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
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
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, 4)
				if _, err := io.ReadFull(conn, payload); err != nil {
					t.Fatal(err)
				}
				if string(payload) != "ping" {
					t.Fatalf("TCP payload: %q", payload)
				}
			}
			packet, err := client.ListenPacketContext(context.Background(), metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			_ = packet.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := packet.WriteTo([]byte("udp"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 16)
			n, _, err := packet.ReadFrom(payload)
			if err != nil || string(payload[:n]) != "udp" {
				t.Fatalf("UDP payload=%q error=%v", payload[:n], err)
			}
			if len(dialer.packets) != 1 {
				t.Fatalf("physical sockets=%d; expected shared QUIC transport", len(dialer.packets))
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := dialer.packets[0].WriteTo([]byte("closed"), addr); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("client Close did not close physical socket: %v", err)
			}
		})
	}
}

type failOncePacket struct {
	net.PacketConn
	once sync.Once
	err  error
}

func (p *failOncePacket) Close() error {
	var failure error
	p.once.Do(func() { failure = p.err })
	if failure != nil {
		return failure
	}
	return p.PacketConn.Close()
}

type failOnceListenConfig struct {
	net.ListenConfig
	packet *failOncePacket
	err    error
}

func (lc *failOnceListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	p, err := lc.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	lc.packet = &failOncePacket{PacketConn: p, err: lc.err}
	return lc.packet, nil
}

func TestHysteria2CloseReportsSocketFailureBeforeWaiting(t *testing.T) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("UDP close failed")
	lc := &failOnceListenConfig{err: want}
	server, err := New(LC.Hysteria2Server{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key}, lc,
		lifecycleTunnel{context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer lc.packet.PacketConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, server.AddrList()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, want) {
			t.Fatalf("Close error=%v", err)
		}
	case <-time.After(300 * time.Millisecond):
		// Release the real socket so the old implementation can unwind too.
		_ = lc.packet.PacketConn.Close()
		<-closed
		t.Fatal("Close hid the socket failure while waiting for a live QUIC session")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
}
func (lifecycleTunnel) HandleTCPConn(c net.Conn, _ *C.Metadata)      { _ = c.Close() }
func (lifecycleTunnel) HandleUDPPacket(p C.UDPPacket, _ *C.Metadata) { p.Drop() }
func (lifecycleTunnel) NatTable() C.NatTable                         { return nil }

func TestHysteria2StopJoinsUnauthenticatedQUICSessions(t *testing.T) {
	forwarding.Enable()
	if err := forwarding.Prepare(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	scope, _ := forwarding.Context(1)
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := New(LC.Hysteria2Server{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key, Users: map[string]string{"test": "password"}}, &net.ListenConfig{}, lifecycleTunnel{scope})
	if err != nil {
		t.Fatal(err)
	}
	preparedCtx, preparedCancel := context.WithTimeout(context.Background(), time.Second)
	preparedConn, preparedErr := quic.DialAddr(preparedCtx, listener.AddrList()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	preparedCancel()
	if preparedErr == nil {
		_ = preparedConn.CloseWithError(0, "")
		t.Fatal("prepared listener admitted QUIC connection")
	}
	if err := forwarding.Activate(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.AddrList()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	// No Hysteria authentication request is sent. Service.Context alone does
	// not close this accepted connection in the pinned sing-quic dependency.
	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatalf("unauthed QUIC remained live: %v", err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("concurrent listener Close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent listener Close did not return")
	}
	if err := forwarding.Prepare(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(LC.Hysteria2Server{}, &net.ListenConfig{}, lifecycleTunnel{scope}); err == nil {
		t.Fatal("stopped generation admitted another constructor")
	}
}
