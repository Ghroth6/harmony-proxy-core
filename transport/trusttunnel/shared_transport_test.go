package trusttunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vmess"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type sharedEchoHandler struct{}

func (sharedEchoHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	defer c.Close()
	_, err := io.Copy(c, c)
	return err
}
func (sharedEchoHandler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	return c.Close()
}

type sharedSocket struct {
	io.Closer
	once sync.Once
	done chan struct{}
}

func (s *sharedSocket) Close() error {
	err := s.Closer.Close()
	s.once.Do(func() { close(s.done) })
	return err
}

type sharedTCP struct {
	net.Conn
	socket *sharedSocket
}

func (c *sharedTCP) Close() error { return c.socket.Close() }

type sharedUDP struct {
	net.PacketConn
	socket *sharedSocket
}

func (c *sharedUDP) Close() error { return c.socket.Close() }

type sharedTestDialer struct {
	calls   atomic.Int32
	sockets chan *sharedSocket
}

func (d *sharedTestDialer) retain(ctx context.Context, c io.Closer) *sharedSocket {
	s := &sharedSocket{Closer: c, done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	go func() { <-s.done; stop() }()
	d.calls.Add(1)
	d.sockets <- s
	return s
}
func (d *sharedTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &sharedTCP{c, d.retain(ctx, c)}, nil
}
func (d *sharedTestDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	c, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &sharedUDP{c, d.retain(ctx, c)}, nil
}

func TestSharedTrustTunnelTransport(t *testing.T) {
	forwarding.Enable()
	for _, useQUIC := range []bool{false, true} {
		t.Run(fmt.Sprintf("quic=%t", useQUIC), func(t *testing.T) {
			certificate := httptest.NewTLSServer(nil)
			defer certificate.Close()
			serverTLS := certificate.TLS.Clone()
			serverTLS.NextProtos = []string{"h2", "h3"}
			service := NewService(ServiceOptions{Ctx: context.Background(), Logger: log.SingLogger, Handler: sharedEchoHandler{}})
			service.UpdateUsers(map[string]string{"user": "pass"})
			var tcp net.Listener
			var udp net.PacketConn
			var address string
			var err error
			if useQUIC {
				udp, err = net.ListenPacket("udp", "127.0.0.1:0")
				if err == nil {
					address = udp.LocalAddr().String()
					defer udp.Close()
				}
			} else {
				tcp, err = net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					address = tcp.Addr().String()
					defer tcp.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = service.Start(tcp, udp, serverTLS); err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			d := &sharedTestDialer{sockets: make(chan *sharedSocket, 8)}
			client, err := NewClient(context.Background(), ClientOptions{Dialer: d, DialOptions: func() []dialer.Option { return nil }, Server: address, Username: "user", Password: "pass", QUIC: useQUIC, TLSConfig: &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			first, err := client.Dial(ctx, "127.0.0.1:80")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			echo := func(c net.Conn) {
				t.Helper()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Write([]byte("data")); err != nil {
					t.Fatal(err)
				}
				var b [4]byte
				if _, err := io.ReadFull(c, b[:]); err != nil {
					t.Fatal(err)
				}
				if string(b[:]) != "data" {
					t.Fatal("echo mismatch")
				}
			}
			echo(first)
			cancel()
			second, err := client.Dial(context.Background(), "127.0.0.1:81")
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			echo(second)
			_ = first.Close()
			echo(second)
			if d.calls.Load() != 1 {
				t.Fatalf("physical dials = %d", d.calls.Load())
			}
			socket := <-d.sockets
			_ = client.Close()
			select {
			case <-socket.done:
			case <-time.After(3 * time.Second):
				t.Fatal("client Close left physical socket open")
			}
		})
	}
}

func TestTrustTunnelCloseStopsHealthWorker(t *testing.T) {
	workers := func() int {
		b := make([]byte, 1<<20)
		n := runtime.Stack(b, true)
		return strings.Count(string(b[:n]), "(*Client).loopHealthCheck(")
	}
	before := workers()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // also release the worker when running the unmodified baseline
	client, err := NewClient(ctx, ClientOptions{HealthCheck: true, TLSConfig: &vmess.TLSConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	client.startOnce.Do(client.start)
	deadline := time.Now().Add(time.Second)
	for workers() != before+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if workers() != before+1 {
		t.Fatal("health worker did not start")
	}
	_ = client.Close()
	deadline = time.Now().Add(time.Second)
	for workers() != before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if workers() != before {
		t.Fatal("client Close left health worker parked")
	}
}
