//go:build with_gvisor

package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/mihomo/component/resolver"
)

// Each DNS waiter captures this candidate's Service. Its lifetime includes the
// actual client read/Close callback and reply write, independently of any shared
// resolver worker retained by the candidate's ResolverOwner.
type dnsBook struct {
	mu        sync.Mutex
	changed   *sync.Cond
	engine    *runEngine
	service   resolver.Service
	mapper    resolver.Enhancer
	observed  DNSObservation
	accepting bool
	pending   int
	fault     bool
	unknown   map[net.Conn]error
}

func newDNSBook(engine *runEngine, service resolver.Service) *dnsBook {
	b := &dnsBook{engine: engine, service: service, unknown: make(map[net.Conn]error)}
	_, b.mapper, _ = engine.cfg.MobileDNSResolvers()
	b.changed = sync.NewCond(&b.mu)
	return b
}

func (b *dnsBook) matches(ip netip.Addr, port uint16) bool {
	return port == 53 && (ip == netip.MustParseAddr("10.111.0.2") || (b.engine.options.IPv6 && ip == netip.MustParseAddr("fd00:111::2")))
}

func (b *dnsBook) activate()      { b.mu.Lock(); b.accepting = true; b.mu.Unlock() }
func (b *dnsBook) stopAdmission() { b.mu.Lock(); b.accepting = false; b.mu.Unlock() }

func (b *dnsBook) admit() bool {
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || b.pending >= MaxDNSWaiters {
		return false
	}
	b.pending++
	return true
}

func (b *dnsBook) finish() {
	b.mu.Lock()
	b.pending--
	b.changed.Broadcast()
	b.mu.Unlock()
}

func (b *dnsBook) handleUDP(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
	b.mu.Lock()
	u := b.engine.udp
	u.mu.Lock()
	if !u.accepting || u.packets >= PacketQueue || !b.admit() {
		u.mu.Unlock()
		b.mu.Unlock()
		return true
	}
	u.packets++ // shares the actual packet-buffer bound with ordinary client UDP.
	u.mu.Unlock()
	b.mu.Unlock()
	views := packet.Data().ToBuffer()
	payload := make([]byte, 0, int(views.Size()))
	views.Apply(func(view *buffer.View) { payload = append(payload, view.AsSlice()...) })
	views.Release()
	source := netip.AddrPortFrom(address(id.RemoteAddress), id.RemotePort)
	target := netip.AddrPortFrom(address(id.LocalAddress), id.LocalPort)
	go func() {
		defer b.finish()
		defer func() { u.mu.Lock(); u.packets--; u.changed.Broadcast(); u.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(b.engine.root, resolver.DefaultDnsRelayTimeout)
		defer cancel()
		size := MTU - 28
		if source.Addr().Is6() {
			size = MTU - 48
		}
		reply, err := resolver.RelayDnsPacketWithService(ctx, payload, make([]byte, size), observedDNSService{b, "udp"})
		if err == nil && ctx.Err() == nil {
			_, _ = u.writeBack(source, target, nil, reply, nil)
		}
	}()
	return true
}

type dnsClientConn struct {
	net.Conn
	book *dnsBook
	once sync.Once
	err  error
}

func (c *dnsClientConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		if c.err != nil {
			c.book.mu.Lock()
			c.book.unknown[c.Conn], c.book.fault = c.err, true
			c.book.mu.Unlock()
			c.book.engine.transfer.failure("DNS_CLIENT_CLEANUP_UNKNOWN")
		}
	})
	return c.err
}

func (b *dnsBook) handleTCP(conn net.Conn) {
	b.mu.Lock()
	admitted := b.admit()
	b.mu.Unlock()
	owned := &dnsClientConn{Conn: conn, book: b}
	if !admitted {
		_ = owned.Close()
		return
	}
	defer b.finish()
	defer owned.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(b.engine.transfer.ctx, func() { defer close(closed); _ = owned.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	_ = resolver.RelayDnsConnWithService(b.engine.root, owned, resolver.DefaultDnsReadTimeout, observedDNSService{b, "tcp"})
}

func (b *dnsBook) wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.pending != 0 {
		b.changed.Wait()
	}
}

func (b *dnsBook) count() int    { b.mu.Lock(); defer b.mu.Unlock(); return b.pending }
func (b *dnsBook) isFault() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.fault }
