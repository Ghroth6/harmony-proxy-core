//go:build with_gvisor

package runtime

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/sing/common/buf"
	N "github.com/metacubex/sing/common/network"
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
	if !b.accepting || b.engine.transfer.ctx.Err() != nil {
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

func (b *dnsBook) handleUDP(source, target netip.AddrPort, payload *buf.Buffer, writer N.PacketWriter) {
	b.mu.Lock()
	u := b.engine.udp
	u.mu.Lock()
	if !u.accepting || !b.admit() {
		u.mu.Unlock()
		b.mu.Unlock()
		payload.Release()
		u.releasePacket()
		return
	}
	u.mu.Unlock()
	b.mu.Unlock()
	go func() {
		defer b.finish()
		defer u.releasePacket()
		defer payload.Release()
		ctx, cancel := context.WithTimeout(b.engine.root, resolver.DefaultDnsRelayTimeout)
		defer cancel()
		size := MTU - 28
		if source.Addr().Is6() {
			size = MTU - 48
		}
		reply, err := resolver.RelayDnsPacketWithService(ctx, payload.Bytes(), make([]byte, size), observedDNSService{b, "udp"})
		if err == nil && ctx.Err() == nil {
			_, _ = u.writeBack(source, target, nil, writer, reply, nil)
		}
	}()
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
