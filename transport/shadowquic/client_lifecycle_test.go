package shadowquic

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-tls"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func shadowTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
}

func TestShadowQUICClientCloseCancelsPendingDial(t *testing.T) {
	entered := make(chan struct{})
	client := NewClient(&ClientOption{Dial: func(ctx context.Context) (*quic.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() { _, err := client.getConn(ctx); dialed <- err }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		cancel()
		<-closed
		<-dialed
		t.Fatal("Close waited behind a dial without cancelling it")
	}
	if err := <-dialed; !errors.Is(err, context.Canceled) {
		t.Fatalf("dial result: %v", err)
	}
	if _, err := client.getConn(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed client admitted dial: %v", err)
	}
}

func TestShadowQUICAssociationCloseUnblocksWrite(t *testing.T) {
	for _, blocked := range []string{"flow-control", "stream-limit"} {
		t.Run(blocked, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			listener, err := quic.Listen(packet, shadowTestTLS(t), &quic.Config{
				EnableDatagrams: true, MaxIncomingUniStreams: 1,
				InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client := NewClient(&ClientOption{UDPOverStream: true, Dial: func(ctx context.Context) (*quic.Conn, error) {
				return quic.DialAddr(ctx, packet.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			}})
			defer client.Close()
			assoc, err := client.ListenPacket(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.CloseWithError(0, "")
			control, err := peer.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCommand(control); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadRequestAddr(control); err != nil {
				t.Fatal(err)
			}
			target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
			payload := make([]byte, maxUDPPacketSize)
			if blocked == "stream-limit" {
				if _, err := assoc.WriteTo([]byte("first"), target); err != nil {
					t.Fatal(err)
				}
				if _, _, err := ReadUDPControl(control); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.AcceptUniStream(ctx); err != nil {
					t.Fatal(err)
				}
				target.Port++
				payload = []byte("second")
			}
			written := make(chan error, 1)
			go func() { _, err := assoc.WriteTo(payload, target); written <- err }()
			if _, _, err := ReadUDPControl(control); err != nil {
				t.Fatal(err)
			}
			if blocked == "flow-control" {
				stream, err := peer.AcceptUniStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var prefix [4]byte
				if _, err := io.ReadFull(stream, prefix[:]); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-written:
				t.Fatalf("write did not reach blocked state: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			closed := make(chan error, 1)
			go func() { closed <- assoc.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(300 * time.Millisecond):
				_ = client.Close()
				<-closed
				t.Fatal("association Close could not interrupt blocked stream write/open")
			}
			select {
			case err := <-written:
				if err == nil {
					t.Fatal("blocked write succeeded after close")
				}
			case <-ctx.Done():
				t.Fatal("writer did not exit")
			}
			if client.conn.closed() {
				t.Fatal("closing one association closed the shared QUIC connection")
			}
			if _, err := client.conn.quicConn.OpenStreamSync(ctx); err != nil {
				t.Fatalf("shared connection unusable: %v", err)
			}
		})
	}
}

func TestShadowQUICSharedConnectionTCPAndUDPModes(t *testing.T) {
	forwarding.Enable()
	for _, overStream := range []bool{false, true} {
		name := "datagram"
		if overStream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			server, err := NewServer(&ServerOption{TLSConfig: shadowTestTLS(t), QUICConfig: &quic.Config{EnableDatagrams: true},
				HandleTcpFn: func(c net.Conn, _ socks5.Addr, _ ...inbound.Addition) error {
					defer c.Close()
					_, err := io.Copy(c, c)
					return err
				},
				HandleUdpFn: func(addr socks5.Addr, p C.UDPPacket, _ ...inbound.Addition) error {
					defer p.Drop()
					_, err := p.WriteBack(p.Data(), AddrToNetAddr(addr))
					return err
				},
			}, packet)
			if err != nil {
				t.Fatal(err)
			}
			go server.Serve()
			defer server.Close()
			dials := 0
			client := NewClient(&ClientOption{UDPOverStream: overStream, Dial: func(ctx context.Context) (*quic.Conn, error) {
				conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
				if err == nil {
					dials++
					context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "dial context canceled") })
				}
				return conn, err
			}})
			defer client.Close()
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 1234}
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
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte("tcp")); err != nil {
					t.Fatal(err)
				}
				var payload [3]byte
				if _, err := io.ReadFull(conn, payload[:]); err != nil {
					t.Fatal(err)
				}
				if string(payload[:]) != "tcp" {
					t.Fatal("TCP payload mismatch")
				}
			}
			udp, err := client.ListenPacket(context.Background(), metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			_ = udp.SetDeadline(time.Now().Add(time.Second))
			if _, err := udp.WriteTo([]byte("udp"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}); err != nil {
				t.Fatal(err)
			}
			var payload [3]byte
			if _, _, err := udp.ReadFrom(payload[:]); err != nil {
				t.Fatal(err)
			}
			if string(payload[:]) != "udp" {
				t.Fatal("UDP payload mismatch")
			}
			if dials != 1 {
				t.Fatalf("shared connection dialed %d times", dials)
			}
			if err := udp.Close(); err != nil {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
