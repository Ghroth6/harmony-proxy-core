package sing_tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/listener/sing"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	D "github.com/miekg/dns"
)

var tunTestGeneration atomic.Uint64

type testBoundTunnel struct {
	C.Tunnel
	ctx context.Context
}

func (t testBoundTunnel) BindContext(ctx context.Context) context.Context {
	return forwarding.Bind(ctx, t.ctx)
}

type dnsServiceFunc func(context.Context, *D.Msg) (*D.Msg, error)

func (f dnsServiceFunc) ServeMsg(ctx context.Context, q *D.Msg) (*D.Msg, error) { return f(ctx, q) }

func tunTestHandler(t *testing.T, active bool) *ListenerHandler {
	t.Helper()
	forwarding.Enable()
	generation := tunTestGeneration.Add(1)
	if err := forwarding.Prepare(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
	ctx, err := forwarding.Context(generation)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		if err := forwarding.Activate(generation); err != nil {
			t.Fatal(err)
		}
	}
	oldService, oldConnect := resolver.DefaultService, connectICMPDestination
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := forwarding.Stop(ctx); err != nil {
			t.Error(err)
		}
		resolver.DefaultService, connectICMPDestination = oldService, oldConnect
	})
	return &ListenerHandler{ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{Tunnel: testBoundTunnel{ctx: ctx}}}, DnsAddrPorts: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")}}
}
func dnsMetadata() M.Metadata                               { return M.Metadata{Destination: M.ParseSocksaddr("192.0.2.1:53")} }
func dnsQuestion() *D.Msg                                   { return new(D.Msg).SetQuestion("tun-lifecycle.test.", D.TypeA) }
func dnsAnswer(_ context.Context, q *D.Msg) (*D.Msg, error) { return new(D.Msg).SetReply(q), nil }
func queryBuffer(t *testing.T) *buf.Buffer {
	t.Helper()
	wire, err := dnsQuestion().Pack()
	if err != nil {
		t.Fatal(err)
	}
	return buf.As(wire)
}
func shortStop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	return forwarding.Stop(ctx)
}
func releaseOnce(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return ch, release
}

type packetWriter struct{ writes atomic.Int64 }

func (w *packetWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	w.writes.Add(1)
	b.Release()
	return nil
}

func TestTUNIngressPreparedAndStoppedRejectDNSAndICMP(t *testing.T) {
	h := tunTestHandler(t, false)
	var calls atomic.Int64
	resolver.DefaultService = dnsServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) { calls.Add(1); return dnsAnswer(ctx, q) })
	for _, stopped := range []bool{false, true} {
		if stopped {
			if err := forwarding.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		server, client := net.Pipe()
		if err := h.NewConnection(context.Background(), server, dnsMetadata()); err == nil {
			t.Fatal("inactive TUN admitted TCP DNS")
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("rejected DNS socket stayed open")
		}
		_ = client.Close()
		h.NewPacket(context.Background(), netip.AddrPort{}, queryBuffer(t), dnsMetadata(), func(N.PacketConn) N.PacketWriter {
			t.Error("inactive TUN initialized UDP writer")
			return &packetWriter{}
		})
		for _, fake := range []bool{false, true} {
			h.DisableICMPForwarding = fake
			if _, err := h.PrepareConnection(N.NetworkICMP, M.Socksaddr{}, M.ParseSocksaddr("203.0.113.7"), nil, time.Second); err == nil {
				t.Fatal("inactive TUN admitted ICMP")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("inactive TUN reached resolver")
	}
}

func TestTUNIngressTCPDNSAnswersWhileRunningAndClosesIdleRead(t *testing.T) {
	h := tunTestHandler(t, true)
	resolver.DefaultService = dnsServiceFunc(dnsAnswer)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- h.NewConnection(context.Background(), server, dnsMetadata()) }()
	question, _ := dnsQuestion().Pack()
	frame := make([]byte, len(question)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(question)))
	copy(frame[2:], question)
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	var length uint16
	if err := binary.Read(client, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, length)
	if _, err := io.ReadFull(client, answer); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("Stop left TCP DNS open")
	}
}

func TestTUNIngressLateUDPDNSResultCannotReplyAfterStop(t *testing.T) {
	h := tunTestHandler(t, true)
	entered := make(chan struct{})
	release, finish := releaseOnce(t)
	resolver.DefaultService = dnsServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		close(entered)
		<-release
		return dnsAnswer(ctx, q)
	})
	writer := &packetWriter{}
	h.NewPacket(context.Background(), netip.AddrPort{}, queryBuffer(t), dnsMetadata(), func(N.PacketConn) N.PacketWriter { return writer })
	<-entered
	if err := shortStop(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop forgot active query: %v", err)
	}
	finish()
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writer.writes.Load() != 0 {
		t.Fatal("cancelled UDP DNS query published a reply")
	}
}

type packetConnection struct {
	packetWriter
	input chan *buf.Buffer
	done  chan struct{}
	once  sync.Once
}

func newPacketConnection() *packetConnection {
	return &packetConnection{input: make(chan *buf.Buffer, 1), done: make(chan struct{})}
}
func (c *packetConnection) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	select {
	case q := <-c.input:
		_, _ = b.Write(q.Bytes())
		q.Release()
		return dnsMetadata().Destination, nil
	case <-c.done:
		return M.Socksaddr{}, net.ErrClosed
	}
}
func (c *packetConnection) Close() error                     { c.once.Do(func() { close(c.done) }); return nil }
func (c *packetConnection) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *packetConnection) SetDeadline(time.Time) error      { return nil }
func (c *packetConnection) SetReadDeadline(time.Time) error  { return nil }
func (c *packetConnection) SetWriteDeadline(time.Time) error { return nil }

func TestTUNIngressDNSPacketConnectionWaitsForChildQuery(t *testing.T) {
	h := tunTestHandler(t, true)
	entered := make(chan struct{})
	release, finish := releaseOnce(t)
	resolver.DefaultService = dnsServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		close(entered)
		<-release
		return dnsAnswer(ctx, q)
	})
	conn := newPacketConnection()
	conn.input <- queryBuffer(t)
	done := make(chan error, 1)
	go func() { done <- h.NewPacketConnection(context.Background(), conn, dnsMetadata()) }()
	<-entered
	if err := shortStop(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop forgot packet-connection query: %v", err)
	}
	<-conn.done
	<-done
	finish()
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conn.writes.Load() != 0 {
		t.Fatal("closed packet connection received late DNS answer")
	}
}

type sharedDNSClient struct {
	entered   chan struct{}
	release   <-chan struct{}
	calls     atomic.Int64
	cancelled atomic.Bool
}

func (c *sharedDNSClient) Address() string  { return "tun-shared-query-test" }
func (c *sharedDNSClient) ResetConnection() {}
func (c *sharedDNSClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	select {
	case <-c.release:
		return dnsAnswer(ctx, q)
	case <-ctx.Done():
		c.cancelled.Store(true)
		return nil, ctx.Err()
	}
}

func TestTUNIngressStopPreservesSharedManagementDNSQuery(t *testing.T) {
	h := tunTestHandler(t, true)
	release, finish := releaseOnce(t)
	client := &sharedDNSClient{entered: make(chan struct{}), release: release}
	r := dns.NewResolverFromClient(client)
	resolver.DefaultService = dns.NewService(r, dns.NewEnhancer(dns.EnhancerConfig{}))
	writer := &packetWriter{}
	h.NewPacket(context.Background(), netip.AddrPort{}, queryBuffer(t), dnsMetadata(), func(N.PacketConn) N.PacketWriter { return writer })
	<-client.entered
	management := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(context.Background(), dnsQuestion()); management <- err }()
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.cancelled.Load() {
		t.Fatal("TUN Stop cancelled shared upstream resolver work")
	}
	finish()
	if err := <-management; err != nil {
		t.Fatal(err)
	}
	if writer.writes.Load() != 0 || client.calls.Load() != 1 {
		t.Fatalf("unexpected writes=%d or upstream calls=%d", writer.writes.Load(), client.calls.Load())
	}
}

type icmpDestination struct {
	closeEntered chan struct{}
	closeRelease <-chan struct{}
	closed       atomic.Bool
	writes       atomic.Int64
}

func (d *icmpDestination) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		if d.closeEntered != nil {
			close(d.closeEntered)
		}
		if d.closeRelease != nil {
			<-d.closeRelease
		}
	}
	return nil
}
func (d *icmpDestination) IsClosed() bool                { return d.closed.Load() }
func (d *icmpDestination) WritePacket(*buf.Buffer) error { d.writes.Add(1); return nil }

type icmpRoute struct{ writes atomic.Int64 }

func (r *icmpRoute) WritePacket([]byte) error { r.writes.Add(1); return nil }

func TestTUNIngressICMPStopWaitsForCloseAndRejectsLatePackets(t *testing.T) {
	h := tunTestHandler(t, true)
	release, finish := releaseOnce(t)
	destination := &icmpDestination{closeEntered: make(chan struct{}), closeRelease: release}
	route := &icmpRoute{}
	var captured tun.DirectRouteContext
	connectICMPDestination = func(ctx context.Context, _ logger.ContextLogger, _ control.Func, _ netip.Addr, r tun.DirectRouteContext, _ time.Duration) (tun.DirectRouteDestination, error) {
		captured = r
		return destination, nil
	}
	owned, err := h.PrepareConnection(N.NetworkICMP, M.Socksaddr{}, M.ParseSocksaddr("203.0.113.7"), route, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.WritePacket(nil); err != nil {
		t.Fatal(err)
	}
	if err := captured.WritePacket(nil); err != nil {
		t.Fatal(err)
	}
	if err := shortStop(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop forgot pending ICMP close: %v", err)
	}
	<-destination.closeEntered
	if !owned.IsClosed() {
		t.Fatal("retired destination remains usable")
	}
	if err := owned.WritePacket(nil); err == nil {
		t.Fatal("retired ICMP request accepted")
	}
	if err := captured.WritePacket(nil); err == nil {
		t.Fatal("retired ICMP reply published")
	}
	finish()
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if destination.writes.Load() != 1 || route.writes.Load() != 1 {
		t.Fatal("late packet reached ICMP transport")
	}
}

func TestTUNIngressRetainsLateICMPConstructorUntilClosed(t *testing.T) {
	h := tunTestHandler(t, true)
	entered := make(chan struct{})
	release, finish := releaseOnce(t)
	destination := &icmpDestination{}
	connectICMPDestination = func(context.Context, logger.ContextLogger, control.Func, netip.Addr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
		close(entered)
		<-release
		return destination, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.PrepareConnection(N.NetworkICMP, M.Socksaddr{}, M.ParseSocksaddr("203.0.113.7"), &icmpRoute{}, time.Second)
		done <- err
	}()
	<-entered
	if err := shortStop(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop forgot ICMP constructor: %v", err)
	}
	finish()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("late constructor published destination: %v", err)
	}
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !destination.closed.Load() {
		t.Fatal("late destination not closed")
	}
}
