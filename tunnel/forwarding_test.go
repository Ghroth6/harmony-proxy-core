package tunnel_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var generation atomic.Uint64

type entryProxy struct {
	*outbound.Base
	tcp func(context.Context, *C.Metadata) (C.Conn, error)
	udp func(context.Context, *C.Metadata) (C.PacketConn, error)
}

func (p *entryProxy) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	return p.tcp(ctx, m)
}
func (p *entryProxy) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	return p.udp(ctx, m)
}

func setupRun(t *testing.T, p *entryProxy) uint64 {
	t.Helper()
	tunnel.EnableForwardingLifecycle()
	tunnel.OnRunning()
	tunnel.UpdateProxies(map[string]C.Proxy{"test": adapter.NewProxy(p)}, nil)
	id := generation.Add(1)
	if err := tunnel.StartForwarding(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tunnel.StopForwarding(ctx); err != nil {
			t.Error(err)
		}
	})
	return id
}
func newEntryProxy() *entryProxy {
	return &entryProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "test", Type: C.Direct, UDP: true})}
}
func await[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("entry did not settle")
		var zero T
		return zero
	}
}
func stopRun(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tunnel.StopForwarding(ctx); err != nil {
		t.Fatal(err)
	}
}
func meta(network C.NetWork) *C.Metadata {
	return &C.Metadata{NetWork: network, Type: C.TUN, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 12345, SpecialProxy: "test"}
}
func enterTCP(m *C.Metadata) (net.Conn, <-chan struct{}) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); tunnel.Tunnel.HandleTCPConn(server, m) }()
	return client, done
}
func assertNoForwardingTrackers(t *testing.T) {
	t.Helper()
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if c.Info().Metadata.ForwardingGeneration != 0 {
			t.Errorf("forwarding tracker remains: %s", c.ID())
		}
		return true
	})
}

func TestForwardingLateTCPDialCannotPublishOrJoinNewRun(t *testing.T) {
	p := newEntryProxy()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	remote, peer := net.Pipe()
	defer peer.Close()
	p.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		entered <- ctx
		<-release
		return outbound.NewConn(remote, p), nil
	}
	setupRun(t, p)
	client, done := enterTCP(meta(C.TCP))
	defer client.Close()
	oldContext := await(t, entered)
	tunnel.CancelForwarding()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := tunnel.StopForwarding(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late dial stop = %v", err)
	}
	if err := tunnel.StartForwarding(context.Background(), generation.Load()+1); err == nil {
		t.Fatal("started while old dial was unresolved")
	}
	close(release)
	stopRun(t)
	await(t, done)
	assertNoForwardingTrackers(t)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late connection was not closed")
	}
	if err := tunnel.StartForwarding(context.Background(), generation.Add(1)); err != nil {
		t.Fatal(err)
	}
	stale := meta(C.TCP)
	stale.Type = C.INNER
	stale.RequestContext = oldContext
	late, lateDone := enterTCP(stale)
	defer late.Close()
	await(t, lateDone)
	select {
	case <-entered:
		t.Fatal("old INNER request joined new generation")
	default:
	}
}

func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []net.Conn
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			_ = c.Close()
		}
	}
}
func exchange(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 'x' {
		t.Fatalf("echo = %q, %v", b, err)
	}
	_ = c.SetDeadline(time.Time{})
}

func TestForwardingStopKeepsManagementAndClosesNestedDialerProxy(t *testing.T) {
	address, cleanup := echoServer(t)
	defer cleanup()
	direct := newEntryProxy()
	direct.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		return outbound.NewConn(c, direct), nil
	}
	outer := newEntryProxy()
	outer.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		c, err := proxydialer.New(direct, true).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		return outbound.NewConn(c, outer), nil
	}
	id := setupRun(t, outer)
	management, err := inner.HandleTcpContext(context.Background(), tunnel.Tunnel, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	exchange(t, management)
	client, done := enterTCP(meta(C.TCP))
	defer client.Close()
	exchange(t, client)
	var owned, unowned int
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if c.Info().Metadata.ForwardingGeneration == id {
			owned++
		} else {
			unowned++
		}
		return true
	})
	if owned != 2 || unowned < 2 {
		t.Fatalf("root/nested tracker owners = %d forwarding, %d management", owned, unowned)
	}
	stopRun(t)
	await(t, done)
	assertNoForwardingTrackers(t)
	exchange(t, management)
	newManagement, err := inner.HandleTcp(tunnel.Tunnel, address, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer newManagement.Close()
	exchange(t, newManagement)
}

type entryPacket struct {
	data    []byte
	local   net.Addr
	dropped chan struct{}
	once    sync.Once
}

func (p *entryPacket) Data() []byte                                { return p.data }
func (p *entryPacket) LocalAddr() net.Addr                         { return p.local }
func (p *entryPacket) WriteBack(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *entryPacket) Drop()                                       { p.once.Do(func() { close(p.dropped) }) }
func newEntryPacket() *entryPacket {
	return &entryPacket{data: []byte("udp"), local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}, dropped: make(chan struct{})}
}

func TestForwardingLateUDPDialIsClosedBeforeStopCompletes(t *testing.T) {
	p := newEntryProxy()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	p.udp = func(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
		entered <- ctx
		<-release
		return outbound.NewPacketConn(raw, p), nil
	}
	setupRun(t, p)
	packet := newEntryPacket()
	tunnel.Tunnel.HandleUDPPacket(packet, meta(C.UDP))
	old := await(t, entered)
	tunnel.CancelForwarding()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = tunnel.StopForwarding(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late UDP dial = %v", err)
	}
	close(release)
	stopRun(t)
	await(t, packet.dropped)
	assertNoForwardingTrackers(t)
	if _, err := raw.WriteTo([]byte("x"), raw.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late UDP socket = %v", err)
	}
	if err := tunnel.StartForwarding(context.Background(), generation.Add(1)); err != nil {
		t.Fatal(err)
	}
	stale := meta(C.UDP)
	stale.RequestContext = old
	packet = newEntryPacket()
	tunnel.Tunnel.HandleUDPPacket(packet, stale)
	await(t, packet.dropped)
}

func TestForwardingUDPManagementSurvivesStop(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 128)
		for {
			n, a, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = echo.WriteTo(b[:n], a)
		}
	}()
	p := newEntryProxy()
	p.udp = func(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
		c, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			return nil, e
		}
		return outbound.NewPacketConn(c, p), nil
	}
	setupRun(t, p)
	management, target, err := inner.HandleUdpContext(context.Background(), tunnel.Tunnel, "udp", echo.LocalAddr().String(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	exchangeUDP := func() {
		t.Helper()
		_ = management.SetDeadline(time.Now().Add(time.Second))
		if _, e := management.WriteTo([]byte("m"), target); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 1)
		if _, _, e := management.ReadFrom(b); e != nil || b[0] != 'm' {
			t.Fatalf("management UDP = %q %v", b, e)
		}
	}
	exchangeUDP()
	packet := newEntryPacket()
	m := meta(C.UDP)
	_ = m.SetRemoteAddress(echo.LocalAddr().String())
	tunnel.Tunnel.HandleUDPPacket(packet, m)
	await(t, packet.dropped)
	stopRun(t)
	assertNoForwardingTrackers(t)
	exchangeUDP()
}

func TestForwardingCancelledParentCannotOpenAdmission(t *testing.T) {
	tunnel.EnableForwardingLifecycle()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tunnel.StartForwarding(ctx, generation.Load()+1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled parent start = %v", err)
	}
	p := newEntryProxy()
	p.tcp = func(context.Context, *C.Metadata) (C.Conn, error) {
		t.Error("cancelled start admitted a root")
		return nil, io.EOF
	}
	tunnel.UpdateProxies(map[string]C.Proxy{"test": adapter.NewProxy(p)}, nil)
	client, done := enterTCP(meta(C.TCP))
	defer client.Close()
	await(t, done)
}

func TestForwardingInnerCancelledContextDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inner.HandleTcpContext(ctx, tunnel.Tunnel, "127.0.0.1:80", "test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := inner.HandleUdpContext(ctx, tunnel.Tunnel, "udp", "127.0.0.1:53", "test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if forwarding.Generation(ctx) != 0 {
		t.Fatal("unowned context was assigned a forwarding generation")
	}
}

func TestForwardingNestedInnerInheritsOwner(t *testing.T) {
	address, cleanup := echoServer(t)
	defer cleanup()
	direct := newEntryProxy()
	direct.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if e != nil {
			return nil, e
		}
		return outbound.NewConn(c, direct), nil
	}
	outer := newEntryProxy()
	outer.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		c, e := inner.HandleTcpContext(ctx, tunnel.Tunnel, address, "direct")
		if e != nil {
			return nil, e
		}
		return outbound.NewConn(c, outer), nil
	}
	id := setupRun(t, outer)
	tunnel.UpdateProxies(map[string]C.Proxy{"test": adapter.NewProxy(outer), "direct": adapter.NewProxy(direct)}, nil)
	client, done := enterTCP(meta(C.TCP))
	defer client.Close()
	exchange(t, client)
	var owned int
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if c.Info().Metadata.ForwardingGeneration == id {
			owned++
		}
		return true
	})
	if owned != 2 {
		t.Fatalf("nested inner owners = %d", owned)
	}
	stopRun(t)
	await(t, done)
	assertNoForwardingTrackers(t)
}

func TestForwardingParentCancellationClosesExistingRun(t *testing.T) {
	p := newEntryProxy()
	address, cleanup := echoServer(t)
	defer cleanup()
	p.tcp = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if e != nil {
			return nil, e
		}
		return outbound.NewConn(c, p), nil
	}
	tunnel.EnableForwardingLifecycle()
	tunnel.OnRunning()
	tunnel.UpdateProxies(map[string]C.Proxy{"test": adapter.NewProxy(p)}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tunnel.StartForwarding(ctx, generation.Add(1)); err != nil {
		t.Fatal(err)
	}
	client, done := enterTCP(meta(C.TCP))
	defer client.Close()
	exchange(t, client)
	cancel()
	await(t, done)
	stopRun(t)
	assertNoForwardingTrackers(t)
}

func TestForwardingMixedHandshakeOwnedBeforeTunnelEntry(t *testing.T) {
	allowed := inbound.AllowedIPs()
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	defer inbound.SetAllowedIPs(allowed)
	tunnel.EnableForwardingLifecycle()
	tunnel.OnRunning()
	id := generation.Add(1)
	if err := tunnel.PrepareForwarding(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	bound, err := tunnel.BoundForwardingTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	l, err := mixed.New("127.0.0.1:0", bound)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dial := func() net.Conn {
		t.Helper()
		c, e := net.Dial("tcp", l.Address())
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		return c
	}
	// Binding the socket does not admit proxy requests before all inputs are ready.
	early := dial()
	_, _ = early.Write([]byte{5, 1, 0})
	if _, e := early.Read(make([]byte, 2)); e == nil {
		t.Fatal("prepared listener admitted a handshake")
	}
	_ = early.Close()
	if err := tunnel.ActivateForwarding(id); err != nil {
		t.Fatal(err)
	}
	client := dial()
	defer client.Close()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(client, greeting); err != nil || greeting[0] != 5 || greeting[1] != 0 {
		t.Fatalf("SOCKS greeting = %v %v", greeting, err)
	}
	// No CONNECT request has reached tunnel yet. Stop must still own this socket.
	stopRun(t)
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("old handshake socket survived stop")
	}
	if err := tunnel.StartForwarding(context.Background(), generation.Add(1)); err != nil {
		t.Fatal(err)
	}
	defer stopRun(t)
	oldListenerClient := dial()
	defer oldListenerClient.Close()
	_, _ = oldListenerClient.Write([]byte{5, 1, 0})
	if _, err := oldListenerClient.Read(make([]byte, 2)); err == nil {
		t.Fatal("old listener attached a session to the new run")
	}
	// Listener-internal INNER paths (reality, shadowtls, masquerade) inherit the
	// frozen owner even when their legacy caller supplies Background implicitly.
	if c, err := inner.HandleTcp(bound, "127.0.0.1:80", "test"); err == nil {
		c.Close()
		t.Fatal("old listener INNER callback escaped ownership")
	}
}
