//go:build with_gvisor

package runtime

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	C "github.com/metacubex/mihomo/constant"
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
}

func newUDPBook(engine *runEngine) *udpBook {
	b := &udpBook{engine: engine, slots: map[netip.AddrPort]*udpSlot{}}
	b.changed = sync.NewCond(&b.mu)
	return b
}

func (b *udpBook) activate() { b.mu.Lock(); b.accepting = true; b.mu.Unlock() }

func (b *udpBook) handlePacket(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
	source, target := address(id.RemoteAddress), address(id.LocalAddress)
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return true
	}
	key := netip.AddrPortFrom(source, id.RemotePort)
	b.mu.Lock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || b.packets >= PacketQueue {
		b.mu.Unlock()
		return true
	}
	slot := b.slots[key]
	if slot == nil {
		if len(b.slots) >= MaxUDPFlows {
			b.mu.Unlock()
			return true
		}
		slot = &udpSlot{}
		b.slots[key] = slot
	}
	if slot.closing || slot.unknown {
		b.mu.Unlock()
		return true
	}
	slot.packets++
	b.packets++
	b.mu.Unlock()
	// ToBuffer clones the validated payload view; the forwarding queue owns an
	// independent copy, so neither gVisor nor a physical receive pool can reuse it.
	views := packet.Data().ToBuffer()
	payload := make([]byte, 0, int(views.Size()))
	views.Apply(func(view *buffer.View) { payload = append(payload, view.AsSlice()...) })
	views.Release()
	owned := &clientUDPPacket{book: b, slot: slot, source: key, target: netip.AddrPortFrom(target, id.LocalPort), payload: payload}
	metadata := &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: source, SrcPort: id.RemotePort, DstIP: target, DstPort: id.LocalPort, RequestContext: b.engine.root}
	metadata.RawDstAddr = net.UDPAddrFromAddrPort(owned.target)
	b.engine.bound.HandleUDPPacket(owned, metadata)
	return true
}

type clientUDPPacket struct {
	book    *udpBook
	slot    *udpSlot
	source  netip.AddrPort
	target  netip.AddrPort
	payload []byte
	drop    sync.Once
}

func (p *clientUDPPacket) Data() []byte        { return p.payload }
func (p *clientUDPPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.source) }
func (p *clientUDPPacket) Drop() {
	p.drop.Do(func() {
		p.payload = nil
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
	source := p.target
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
	proto := header.IPv4ProtocolNumber
	if p.source.Addr().Is6() {
		proto = header.IPv6ProtocolNumber
		if source.Addr().Is4() {
			source = netip.AddrPortFrom(netip.AddrFrom16(source.Addr().As16()), source.Port())
		}
	} else if !source.Addr().Is4() {
		return 0, errors.New("UDP reply address family mismatch")
	}
	b := p.book
	b.mu.Lock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil || p.slot.closing || p.slot.unknown || b.slots[p.source] != p.slot || b.writes >= MaxUDPWrites {
		b.mu.Unlock()
		return 0, context.Canceled
	}
	b.writes++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.writes--; b.changed.Broadcast(); b.mu.Unlock() }()
	route, routeErr := b.engine.stack.FindRoute(1, stackAddress(source.Addr()), stackAddress(p.source.Addr()), proto, false)
	if routeErr != nil {
		return 0, gonet.TranslateNetstackError(routeErr)
	}
	defer route.Release()
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()), Payload: buffer.MakeWithData(append([]byte{}, data...))})
	defer packet.DecRef()
	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHeader := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	length := uint16(packet.Size())
	udpHeader.Encode(&header.UDPFields{SrcPort: source.Port(), DstPort: p.source.Port(), Length: length})
	if route.RequiresTXTransportChecksum() {
		xsum := udpHeader.CalculateChecksum(checksum.Combine(route.PseudoHeaderChecksum(header.UDPProtocolNumber, length), packet.Data().Checksum()))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHeader.SetChecksum(xsum)
	}
	if err := route.WritePacket(stack.NetworkHeaderParams{Protocol: header.UDPProtocolNumber, TTL: route.DefaultTTL()}, packet); err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return 0, gonet.TranslateNetstackError(err)
	}
	route.Stats().UDP.PacketsSent.Increment()
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

func stackAddress(ip netip.Addr) tcpip.Address {
	if ip.Is4() {
		return tcpip.AddrFrom4(ip.As4())
	}
	return tcpip.AddrFrom16(ip.As16())
}
