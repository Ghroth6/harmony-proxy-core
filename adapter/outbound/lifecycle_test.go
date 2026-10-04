package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

type leaseTestAdapter struct {
	*Base
	dial       func(context.Context) (C.Conn, error)
	listen     func(context.Context) (C.PacketConn, error)
	close      func() error
	closeCalls atomic.Int32
}

func newLeaseTestAdapter() *leaseTestAdapter {
	return &leaseTestAdapter{Base: NewBase(BaseOption{Name: "leased", Addr: "proxy.test:443", Type: C.AnyTLS, ProviderName: "subscription", UDP: true})}
}

func (a *leaseTestAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	return a.dial(ctx)
}

func (a *leaseTestAdapter) ListenPacketContext(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
	return a.listen(ctx)
}

func (a *leaseTestAdapter) Close() error {
	a.closeCalls.Add(1)
	if a.close != nil {
		return a.close()
	}
	return nil
}

func leaseAdapter(a *leaseTestAdapter) *autoCloseProxyAdapter {
	return NewAutoCloseProxyAdapter(a).(*autoCloseProxyAdapter)
}

func waitLeaseRetired(t *testing.T, p *autoCloseProxyAdapter) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return p.WaitRetired(ctx)
}

func assertLeasePending(t *testing.T, p *autoCloseProxyAdapter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if err := p.WaitRetired(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retirement finished before owned work: %v", err)
	}
}

func receiveLeaseSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("owned operation did not reach its barrier")
	}
}

func TestAdapterRetireTCPPreservesExistingConnectionAndRejectsNewDials(t *testing.T) {
	a := newLeaseTestAdapter()
	left, right := net.Pipe()
	defer right.Close()
	a.dial = func(context.Context) (C.Conn, error) { return NewConn(left, a), nil }
	p := leaseAdapter(a)
	c, err := p.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.Retire()
	if _, err := p.DialContext(context.Background(), &C.Metadata{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("new TCP dial: %v", err)
	}
	if _, err := p.ListenPacketContext(context.Background(), &C.Metadata{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("new UDP listen: %v", err)
	}
	assertLeasePending(t, p)
	writeDone := make(chan error, 1)
	go func() { _, err := right.Write([]byte("still alive")); writeDone <- err }()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 11)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "still alive" {
		t.Fatalf("retired connection read: %q, %v", b, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if a.closeCalls.Load() != 0 {
		t.Fatal("protocol closed while TCP lease was active")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if a.closeCalls.Load() != 1 {
		t.Fatalf("protocol Close calls: %d", a.closeCalls.Load())
	}
}

func TestAdapterRetireUDPDrainsExistingPacketConnection(t *testing.T) {
	a := newLeaseTestAdapter()
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer peer.Close()
	a.listen = func(context.Context) (C.PacketConn, error) { return NewPacketConn(raw, a), nil }
	p := leaseAdapter(a)
	c, err := p.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.Retire()
	assertLeasePending(t, p)
	if _, err := c.WriteTo([]byte("out"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 8)
	n, _, err := peer.ReadFrom(b)
	if err != nil || string(b[:n]) != "out" {
		t.Fatalf("retired UDP write: %q, %v", b[:n], err)
	}
	if _, err := peer.WriteTo([]byte("in"), raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	data, put, _, err := c.WaitReadFrom()
	if put != nil {
		defer put()
	}
	if err != nil || string(data) != "in" {
		t.Fatalf("retired buffered UDP read: %q, %v", data, err)
	}
	if !reflect.DeepEqual(c.Chains(), C.Chain{"leased"}) || c.EgressType() != C.AnyTLS {
		t.Fatal("UDP metadata lost")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterRetireWaitsForAdmittedDialWithoutCancelingIt(t *testing.T) {
	a := newLeaseTestAdapter()
	entered, release := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	a.dial = func(ctx context.Context) (C.Conn, error) {
		close(entered)
		<-release
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return NewConn(left, a), nil
	}
	p := leaseAdapter(a)
	result := make(chan C.Conn, 1)
	errs := make(chan error, 1)
	go func() { c, err := p.DialContext(context.Background(), &C.Metadata{}); result <- c; errs <- err }()
	receiveLeaseSignal(t, entered)
	p.Retire()
	assertLeasePending(t, p)
	if a.closeCalls.Load() != 0 {
		t.Fatal("dial creation was not leased")
	}
	close(release)
	c, err := <-result, <-errs
	if err != nil || c == nil {
		t.Fatalf("admitted dial canceled by natural retirement: %v", err)
	}
	assertLeasePending(t, p)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
}

type leaseCloseConn struct {
	C.Conn
	close func() error
	calls atomic.Int32
}

func (c *leaseCloseConn) Close() error {
	c.calls.Add(1)
	if c.close != nil {
		return c.close()
	}
	return c.Conn.Close()
}

type leaseClosePacket struct {
	C.PacketConn
	close func() error
	calls atomic.Int32
}

func (c *leaseClosePacket) Close() error {
	c.calls.Add(1)
	if c.close != nil {
		return c.close()
	}
	return c.PacketConn.Close()
}

func TestAdapterForceCloseWaitsForConnectionAndProtocolClose(t *testing.T) {
	a := newLeaseTestAdapter()
	tcpEntered, tcpRelease := make(chan struct{}), make(chan struct{})
	udpEntered, udpRelease := make(chan struct{}), make(chan struct{})
	poolEntered, poolRelease := make(chan struct{}), make(chan struct{})
	tcp := &leaseCloseConn{close: func() error { close(tcpEntered); <-tcpRelease; return nil }}
	udp := &leaseClosePacket{close: func() error { close(udpEntered); <-udpRelease; return nil }}
	a.dial = func(context.Context) (C.Conn, error) { return tcp, nil }
	a.listen = func(context.Context) (C.PacketConn, error) { return udp, nil }
	a.close = func() error { close(poolEntered); <-poolRelease; return nil }
	p := leaseAdapter(a)
	c, err := p.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := p.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	receiveLeaseSignal(t, tcpEntered)
	receiveLeaseSignal(t, udpEntered)
	receiveLeaseSignal(t, poolEntered)
	assertLeasePending(t, p)
	close(poolRelease)
	close(tcpRelease)
	assertLeasePending(t, p)
	close(udpRelease)
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if tcp.calls.Load() != 1 || udp.calls.Load() != 1 || a.closeCalls.Load() != 1 {
		t.Fatalf("Close repeated: tcp=%d udp=%d pool=%d", tcp.calls.Load(), udp.calls.Load(), a.closeCalls.Load())
	}
}

func TestAdapterForceCloseCancelsDialAndJoinsLateConnection(t *testing.T) {
	a := newLeaseTestAdapter()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	poolClosed := make(chan struct{})
	lateClosed, lateRelease := make(chan struct{}), make(chan struct{})
	raw := &leaseCloseConn{close: func() error { close(lateClosed); <-lateRelease; return nil }}
	a.dial = func(ctx context.Context) (C.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		// Simulate a protocol that cannot finish its dial until its pool closes.
		<-poolClosed
		<-release
		return raw, nil
	}
	a.close = func() error { close(poolClosed); return nil }
	p := leaseAdapter(a)
	dialDone := make(chan error, 1)
	go func() {
		c, err := p.DialContext(context.Background(), &C.Metadata{})
		if c != nil {
			t.Error("late connection escaped force-close")
		}
		dialDone <- err
	}()
	receiveLeaseSignal(t, entered)
	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	receiveLeaseSignal(t, canceled)
	receiveLeaseSignal(t, poolClosed)
	assertLeasePending(t, p)
	close(release)
	receiveLeaseSignal(t, lateClosed)
	assertLeasePending(t, p)
	close(lateRelease)
	if err := <-dialDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late dial error: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
	if raw.calls.Load() != 1 {
		t.Fatalf("late Close calls: %d", raw.calls.Load())
	}
}

func TestAdapterDialFailureClosesAllocatedConnectionAndRetainsCleanupError(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "UDP"}[packet], func(t *testing.T) {
			a := newLeaseTestAdapter()
			dialErr, closeErr := errors.New("dial failure"), errors.New("connection close failure")
			raw := &leaseCloseConn{close: func() error { return closeErr }}
			pc := &leaseClosePacket{close: func() error { return closeErr }}
			a.dial = func(context.Context) (C.Conn, error) { return raw, dialErr }
			a.listen = func(context.Context) (C.PacketConn, error) { return pc, dialErr }
			p := leaseAdapter(a)
			var err error
			if packet {
				_, err = p.ListenPacketContext(context.Background(), &C.Metadata{})
			} else {
				_, err = p.DialContext(context.Background(), &C.Metadata{})
			}
			if !errors.Is(err, dialErr) || !errors.Is(err, closeErr) {
				t.Fatalf("allocation cleanup errors: %v", err)
			}
			p.Retire()
			if err := waitLeaseRetired(t, p); !errors.Is(err, closeErr) {
				t.Fatalf("lost cleanup failure: %v", err)
			}
			if err := p.Close(); !errors.Is(err, closeErr) {
				t.Fatalf("lost repeated cleanup failure: %v", err)
			}
			if raw.calls.Load()+pc.calls.Load() != 1 || a.closeCalls.Load() != 1 {
				t.Fatal("cleanup repeated")
			}
		})
	}
}

func TestAdapterRetirementRetainsStreamAndPoolErrorsExactlyOnce(t *testing.T) {
	a := newLeaseTestAdapter()
	streamErr, poolErr := errors.New("stream close failure"), errors.New("pool close failure")
	raw := &leaseCloseConn{close: func() error { return streamErr }}
	a.dial = func(context.Context) (C.Conn, error) { return raw, nil }
	a.close = func() error { return poolErr }
	p := leaseAdapter(a)
	c, err := p.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	p.Retire()
	if err := c.Close(); !errors.Is(err, streamErr) {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := waitLeaseRetired(t, p); !errors.Is(err, streamErr) || !errors.Is(err, poolErr) {
			t.Fatalf("lost retained errors: %v", err)
		}
		if err := p.Close(); !errors.Is(err, streamErr) || !errors.Is(err, poolErr) {
			t.Fatalf("repeated Close: %v", err)
		}
		if err := c.Close(); !errors.Is(err, streamErr) {
			t.Fatalf("repeated stream Close: %v", err)
		}
	}
	if raw.calls.Load() != 1 || a.closeCalls.Load() != 1 {
		t.Fatal("failure caused repeated Close")
	}
}

type leaseMetadataConn struct {
	C.Conn
	reads, writes, readCloses, writeCloses, handshakes int
}

func (c *leaseMetadataConn) ReadBuffer(b *buf.Buffer) error {
	c.reads++
	_, err := b.WriteString("buffered")
	return err
}
func (c *leaseMetadataConn) WriteBuffer(b *buf.Buffer) error { c.writes++; b.Release(); return nil }
func (c *leaseMetadataConn) CloseRead() error                { c.readCloses++; return nil }
func (c *leaseMetadataConn) CloseWrite() error               { c.writeCloses++; return nil }
func (c *leaseMetadataConn) NeedHandshake() bool             { return true }
func (c *leaseMetadataConn) HandshakeSuccess() error         { c.handshakes++; return nil }

func TestAdapterLeasedTCPPreservesBuffersMetadataHandshakeAndHalfClose(t *testing.T) {
	a := newLeaseTestAdapter()
	left, right := net.Pipe()
	defer right.Close()
	raw := &leaseMetadataConn{Conn: NewConn(left, a)}
	a.dial = func(context.Context) (C.Conn, error) { return raw, nil }
	p := leaseAdapter(a)
	c, err := p.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	p.Retire()
	if !N.NeedHandshake(c) {
		t.Fatal("handshake discovery hidden")
	}
	if err := SN.ReportHandshakeSuccess(c); err != nil || raw.handshakes != 1 {
		t.Fatal("handshake callback hidden", err)
	}
	if c.(interface{ Upstream() any }).Upstream() != raw {
		t.Fatal("upstream changed")
	}
	if !reflect.DeepEqual(c.Chains(), C.Chain{"leased"}) || !reflect.DeepEqual(c.ProviderChains(), C.Chain{"subscription"}) || c.EgressType() != C.AnyTLS || c.RemoteDestination() != raw.RemoteDestination() {
		t.Fatal("connection metadata changed")
	}
	group := NewBase(BaseOption{Name: "group", ProviderName: "group-provider", Type: C.Selector})
	c.AppendToChains(group)
	if !reflect.DeepEqual(c.Chains(), C.Chain{"leased", "group"}) || c.EgressType() != C.AnyTLS {
		t.Fatal("chain append changed egress")
	}
	b := buf.New()
	if err := c.ReadBuffer(b); err != nil || string(b.Bytes()) != "buffered" {
		t.Fatal("extended buffer read", err)
	}
	if err := c.WriteBuffer(b); err != nil || raw.reads != 1 || raw.writes != 1 {
		t.Fatal("extended buffer write", err)
	}
	if err := c.(SN.WriteCloser).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := c.(SN.ReadCloser).CloseRead(); err != nil {
		t.Fatal(err)
	}
	assertLeasePending(t, p)
	if raw.readCloses != 1 || raw.writeCloses != 1 || a.closeCalls.Load() != 0 {
		t.Fatal("half close released full lease")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
}

type leaseMetadataPacket struct {
	C.PacketConn
	resolved, reads, writes int
}

func (c *leaseMetadataPacket) ResolveUDP(_ context.Context, m *C.Metadata) error {
	c.resolved++
	m.DstIP = netip.MustParseAddr("192.0.2.1")
	return nil
}
func (c *leaseMetadataPacket) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	c.reads++
	_, err := b.WriteString("packet")
	return M.ParseSocksaddr("192.0.2.2:53"), err
}
func (c *leaseMetadataPacket) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	c.writes++
	b.Release()
	return nil
}

func TestAdapterLeasedUDPPreservesResolverAndSingBuffers(t *testing.T) {
	a := newLeaseTestAdapter()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raw := &leaseMetadataPacket{PacketConn: NewPacketConn(udp, a)}
	a.listen = func(context.Context) (C.PacketConn, error) { return raw, nil }
	p := leaseAdapter(a)
	c, err := p.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	m := &C.Metadata{Host: "example.test"}
	if err := c.ResolveUDP(context.Background(), m); err != nil || m.DstIP.String() != "192.0.2.1" || raw.resolved != 1 {
		t.Fatal("ResolveUDP lost", err)
	}
	sing, ok := c.(SN.NetPacketConn)
	if !ok {
		t.Fatal("sing packet capability hidden")
	}
	b := buf.NewPacket()
	dest, err := sing.ReadPacket(b)
	if err != nil || string(b.Bytes()) != "packet" || dest.String() != "192.0.2.2:53" {
		t.Fatal("sing packet read changed", err)
	}
	if err := sing.WritePacket(b, dest); err != nil || raw.reads != 1 || raw.writes != 1 {
		t.Fatal("sing packet write changed", err)
	}
	if c.(interface{ Upstream() any }).Upstream() != raw || !reflect.DeepEqual(c.ProviderChains(), C.Chain{"subscription"}) || c.EgressType() != C.AnyTLS {
		t.Fatal("UDP metadata lost")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	p.Retire()
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterConcurrentRetireCloseAndConnectionClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		a := newLeaseTestAdapter()
		raw := &leaseCloseConn{close: func() error { return nil }}
		a.dial = func(context.Context) (C.Conn, error) { return raw, nil }
		p := leaseAdapter(a)
		c, err := p.DialContext(context.Background(), &C.Metadata{})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(3)
			go func() { defer wg.Done(); p.Retire() }()
			go func() {
				defer wg.Done()
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			}()
			go func() {
				defer wg.Done()
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if raw.calls.Load() != 1 || a.closeCalls.Load() != 1 {
			t.Fatalf("iteration %d repeated Close", i)
		}
	}
}

func TestAdapterConnectionContextLivesUntilFullClose(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "UDP"}[packet], func(t *testing.T) {
			a := newLeaseTestAdapter()
			var admitted context.Context
			a.dial = func(ctx context.Context) (C.Conn, error) {
				admitted = ctx
				return &leaseCloseConn{close: func() error { return nil }}, nil
			}
			a.listen = func(ctx context.Context) (C.PacketConn, error) {
				admitted = ctx
				return &leaseClosePacket{close: func() error { return nil }}, nil
			}
			p := leaseAdapter(a)
			var c io.Closer
			var err error
			if packet {
				c, err = p.ListenPacketContext(context.Background(), &C.Metadata{})
			} else {
				c, err = p.DialContext(context.Background(), &C.Metadata{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if admitted.Err() != nil {
				t.Fatal("successful connection canceled its context")
			}
			p.Retire()
			if admitted.Err() != nil {
				t.Fatal("natural retirement canceled existing context")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(admitted.Err(), context.Canceled) {
				t.Fatal("closed connection context not released")
			}
			if err := waitLeaseRetired(t, p); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdapterForceRetireWaitsForAdmittedUDPAndItsLateClose(t *testing.T) {
	a := newLeaseTestAdapter()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	closed, closeRelease := make(chan struct{}), make(chan struct{})
	closeErr := errors.New("late UDP Close failure")
	raw := &leaseClosePacket{close: func() error { close(closed); <-closeRelease; return closeErr }}
	a.listen = func(ctx context.Context) (C.PacketConn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return raw, nil
	}
	p := leaseAdapter(a)
	listenDone := make(chan error, 1)
	go func() {
		c, err := p.ListenPacketContext(context.Background(), &C.Metadata{})
		if c != nil {
			t.Error("late UDP connection escaped forced retirement")
		}
		listenDone <- err
	}()
	receiveLeaseSignal(t, entered)
	p.ForceRetire()
	receiveLeaseSignal(t, canceled)
	assertLeasePending(t, p)
	close(release)
	receiveLeaseSignal(t, closed)
	assertLeasePending(t, p)
	close(closeRelease)
	if err := <-listenDone; !errors.Is(err, net.ErrClosed) || !errors.Is(err, closeErr) {
		t.Fatalf("late UDP result: %v", err)
	}
	if err := waitLeaseRetired(t, p); !errors.Is(err, closeErr) {
		t.Fatalf("lost late UDP close error: %v", err)
	}
	if err := p.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("lost error on repeated force-close: %v", err)
	}
	if raw.calls.Load() != 1 || a.closeCalls.Load() != 1 {
		t.Fatal("late UDP cleanup repeated")
	}
}

func TestAdapterTCPHalfCloseKeepsReverseDirectionAndLease(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	a := newLeaseTestAdapter()
	a.dial = func(ctx context.Context) (C.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return NewConn(c, a), nil
	}
	p := leaseAdapter(a)
	c, err := p.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer peer.Close()
	p.Retire()
	if err := c.(SN.WriteCloser).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 8)
	if _, err := peer.Read(b); !errors.Is(err, io.EOF) {
		t.Fatalf("half-close did not reach peer: %v", err)
	}
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "response" {
		t.Fatalf("half-close killed reverse flow: %q, %v", b, err)
	}
	assertLeasePending(t, p)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitLeaseRetired(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterCanceledOrFailedDialDoesNotHoldRetirement(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "UDP"}[packet], func(t *testing.T) {
			a := newLeaseTestAdapter()
			var calls int
			dialErr := errors.New("creation failed")
			a.dial = func(context.Context) (C.Conn, error) { calls++; return nil, dialErr }
			a.listen = func(context.Context) (C.PacketConn, error) { calls++; return nil, dialErr }
			p := leaseAdapter(a)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var err error
			if packet {
				_, err = p.ListenPacketContext(ctx, &C.Metadata{})
			} else {
				_, err = p.DialContext(ctx, &C.Metadata{})
			}
			if !errors.Is(err, context.Canceled) || calls != 0 {
				t.Fatalf("canceled dial admitted: %v, calls=%d", err, calls)
			}
			if packet {
				_, err = p.ListenPacketContext(context.Background(), &C.Metadata{})
			} else {
				_, err = p.DialContext(context.Background(), &C.Metadata{})
			}
			if !errors.Is(err, dialErr) || calls != 1 {
				t.Fatalf("dial error changed: %v", err)
			}
			p.Retire()
			if err := waitLeaseRetired(t, p); err != nil {
				t.Fatalf("failed dial blocked cleanup: %v", err)
			}
		})
	}
}

func TestAdapterRetirementRetainsUnknownCloseOwnersButNotAlreadyClosed(t *testing.T) {
	unknown := errors.New("descriptor close not confirmed")
	for _, tc := range []struct {
		name     string
		err      error
		retained int
	}{
		{"already closed", fmt.Errorf("closed socket: %w", net.ErrClosed), 0},
		{"unknown", unknown, 1},
		{"joined sibling", errors.Join(net.ErrClosed, unknown), 1},
		{"wrapped joined sibling", fmt.Errorf("close: %w", errors.Join(net.ErrClosed, unknown)), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newLeaseTestAdapter()
			raw := &leaseCloseConn{close: func() error { return tc.err }}
			a.dial = func(context.Context) (C.Conn, error) { return raw, nil }
			a.close = func() error { return fmt.Errorf("already closed pool: %w", net.ErrClosed) }
			p := leaseAdapter(a)
			c, err := p.DialContext(context.Background(), &C.Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			p.Retire()
			_ = c.Close()
			err = waitLeaseRetired(t, p)
			if tc.retained == 0 && err != nil {
				t.Fatalf("known closed became cleanup failure: %v", err)
			}
			if tc.retained > 0 && !errors.Is(err, unknown) {
				t.Fatalf("lost unknown sibling: %v", err)
			}
			p.lifetime.mu.Lock()
			retained := len(p.lifetime.failed)
			for lease := range p.lifetime.failed {
				if lease.closer != raw {
					t.Error("unknown resource owner not retained")
				}
			}
			p.lifetime.mu.Unlock()
			if retained != tc.retained {
				t.Fatalf("retained %d owners, want %d", retained, tc.retained)
			}
			_ = p.Close()
			if raw.calls.Load() != 1 || a.closeCalls.Load() != 1 {
				t.Fatal("unknown cleanup was retried")
			}
		})
	}
}
