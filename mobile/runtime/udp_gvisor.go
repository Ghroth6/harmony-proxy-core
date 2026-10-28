//go:build with_gvisor

package runtime

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	C "github.com/metacubex/mihomo/constant"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// Slots follow the actual tunnel NAT source key, not a guessed UDP idle timer.
// A packet buffer can finish before the retained sender and read worker finish.
type udpSlot struct {
	packets int
	flow    bool
	closing bool
	unknown bool
}

type udpBook struct {
	mu        sync.Mutex
	changed   *sync.Cond
	engine    *runEngine
	slots     map[netip.AddrPort]*udpSlot
	accepting bool
	packets   int
	writes    int
	fault     bool
	forwarder *tun.UDPForwarder
}

func newUDPBook(engine *runEngine) *udpBook {
	b := &udpBook{engine: engine, slots: map[netip.AddrPort]*udpSlot{}}
	b.changed = sync.NewCond(&b.mu)
	b.forwarder = tun.NewUDPForwarder(engine.root, engine.stack, b)
	return b
}

func (b *udpBook) activate() { b.mu.Lock(); b.accepting = true; b.mu.Unlock() }

func (b *udpBook) handlePacket(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
	source, target := address(id.RemoteAddress), address(id.LocalAddress)
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return true
	}
	b.mu.Lock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || b.packets >= PacketQueue {
		b.mu.Unlock()
		return true
	}
	b.packets++ // Reserve before upstream copies the payload, including DNS.
	b.mu.Unlock()
	return b.forwarder.HandlePacket(id, packet)
}

// Only NewPacket is called by the upstream UDP forwarder. Its payload and
// reply writer are transferred into the actual Mihomo packet/flow lifetime.
func (b *udpBook) NewPacket(_ context.Context, key netip.AddrPort, payload *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	writer := init(nil) // gVisor's writer is stateless with respect to a NAT conn.
	if b.engine.dns != nil && b.engine.dns.matches(metadata.Destination.Addr, metadata.Destination.Port) {
		b.engine.dns.handleUDP(key, metadata.Destination.AddrPort(), payload, writer)
		return
	}
	b.mu.Lock()
	slot := b.slots[key]
	if slot == nil {
		slot = &udpSlot{}
		b.slots[key] = slot
	}
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || slot.closing || slot.unknown {
		b.reclaimLocked(key, slot)
		b.mu.Unlock()
		payload.Release()
		b.releasePacket()
		return
	}
	slot.packets++
	b.mu.Unlock()
	owned := &clientUDPPacket{book: b, slot: slot, source: key, target: metadata.Destination.AddrPort(), payload: payload, writer: writer}
	request := &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: key.Addr(), SrcPort: key.Port(), DstIP: owned.target.Addr(), DstPort: owned.target.Port(), RequestContext: b.engine.root}
	request.RawDstAddr = net.UDPAddrFromAddrPort(owned.target)
	b.engine.bound.HandleUDPPacket(owned, request)
}

func (b *udpBook) releasePacket() {
	b.mu.Lock()
	b.packets--
	b.changed.Broadcast()
	b.mu.Unlock()
}

func (*udpBook) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, errors.ErrUnsupported
}
func (*udpBook) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	_ = conn.Close()
	return errors.ErrUnsupported
}
func (b *udpBook) NewError(context.Context, error) { b.engine.transfer.failure("UDP_FORWARDER") }

type clientUDPPacket struct {
	book    *udpBook
	slot    *udpSlot
	source  netip.AddrPort
	target  netip.AddrPort
	payload *buf.Buffer
	writer  N.PacketWriter
	drop    sync.Once
}

func (p *clientUDPPacket) Data() []byte        { return p.payload.Bytes() }
func (p *clientUDPPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.source) }
func (p *clientUDPPacket) Drop() {
	p.drop.Do(func() {
		p.payload.Release()
		b := p.book
		b.mu.Lock()
		p.slot.packets--
		b.packets--
		b.reclaimLocked(p.source, p.slot)
		b.changed.Broadcast()
		b.mu.Unlock()
	})
}

func (b *udpBook) reclaimLocked(key netip.AddrPort, slot *udpSlot) {
	if slot.packets == 0 && !slot.flow && !slot.unknown {
		if b.slots[key] == slot {
			delete(b.slots, key)
		}
	}
}

func (p *clientUDPPacket) RetainUDPFlow() (func(), func(error), bool) {
	b := p.book
	b.mu.Lock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || b.slots[p.source] != p.slot || p.slot.flow || p.slot.closing || p.slot.unknown {
		b.mu.Unlock()
		return nil, nil, false
	}
	p.slot.flow = true
	b.mu.Unlock()
	var closeOnce, completeOnce sync.Once
	closeAdmission := func() {
		closeOnce.Do(func() {
			b.mu.Lock()
			p.slot.closing = true
			b.changed.Broadcast()
			b.mu.Unlock()
		})
	}
	complete := func(err error) {
		closeAdmission()
		completeOnce.Do(func() {
			b.mu.Lock()
			p.slot.flow = false
			if err != nil {
				p.slot.unknown, b.fault = true, true
			}
			b.reclaimLocked(p.source, p.slot)
			b.changed.Broadcast()
			b.mu.Unlock()
			if err != nil {
				b.engine.transfer.failure("UDP_CLEANUP_UNKNOWN")
			}
		})
	}
	return closeAdmission, complete, true
}

// WriteBack survives Drop: its tuple and slot are immutable and independent of
// the original payload. Nil source preserves the original fake-IP destination.
func (p *clientUDPPacket) WriteBack(data []byte, from net.Addr) (int, error) {
	return p.book.writeBack(p.source, p.target, p.slot, p.writer, data, from)
}

func (b *udpBook) writeBack(client, target netip.AddrPort, slot *udpSlot, writer N.PacketWriter, data []byte, from net.Addr) (int, error) {
	source := target
	if from != nil {
		addr, ok := from.(*net.UDPAddr)
		if !ok || addr == nil || addr.Port < 0 || addr.Port > math.MaxUint16 {
			return 0, errors.New("invalid UDP reply source")
		}
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return 0, errors.New("invalid UDP reply address")
		}
		source = netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port))
	}
	if !source.IsValid() || len(data) > math.MaxUint16-header.UDPMinimumSize {
		return 0, errors.New("invalid UDP reply bounds")
	}
	if client.Addr().Is6() {
		if source.Addr().Is4() {
			source = netip.AddrPortFrom(netip.AddrFrom16(source.Addr().As16()), source.Port())
		}
	} else if !source.Addr().Is4() {
		return 0, errors.New("UDP reply address family mismatch")
	}
	b.mu.Lock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || (slot != nil && (slot.closing || slot.unknown || b.slots[client] != slot)) {
		b.mu.Unlock()
		return 0, context.Canceled
	}
	b.writes++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.writes--; b.changed.Broadcast(); b.mu.Unlock() }()
	// This synchronous write retains its caller's owner. The real gVisor link
	// queue bounds buffered replies and returns a transport error when full;
	// counting writers is a stop barrier, not a second packet-admission ceiling.
	packet := buf.NewSize(len(data))
	_, _ = packet.Write(data)
	// Destination is validated above; the upstream writer releases this buffer
	// on every route/write result and owns IP/UDP encoding and checksums.
	if err := writer.WritePacket(packet, M.SocksaddrFromNetIP(source)); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (b *udpBook) stopAdmission() {
	b.mu.Lock()
	b.accepting = false
	for _, slot := range b.slots {
		slot.closing = true
	}
	b.changed.Broadcast()
	b.mu.Unlock()
}

func (b *udpBook) wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		active := false
		for _, slot := range b.slots {
			active = active || slot.flow
		}
		if !active && b.packets == 0 && b.writes == 0 {
			return
		}
		b.changed.Wait()
	}
}

func (b *udpBook) counts() (flows, packets, writes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, slot := range b.slots {
		if slot.flow || slot.unknown {
			flows++
		}
	}
	return flows, b.packets, b.writes
}

func (b *udpBook) isFault() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.fault }
