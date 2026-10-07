//go:build with_gvisor

package runtime

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	C "github.com/metacubex/mihomo/constant"
)

type tcpSlot struct {
	claimed    bool
	forwarding bool
}

// Only this wrapper has access to inner. It reserves before inner may schedule
// a callback, rejects outer duplicates/capacity itself, and retains a slot until
// the complete callback and forwarding handler have actually returned.
type tcpBook struct {
	mu           sync.Mutex
	changed      *sync.Cond
	engine       *runEngine
	inner        *tcp.Forwarder
	slots        map[stack.TransportEndpointID]*tcpSlot
	accepting    bool
	constructors int
	fault        bool
}

func newTCPBook(engine *runEngine) *tcpBook {
	book := &tcpBook{engine: engine, slots: map[stack.TransportEndpointID]*tcpSlot{}}
	book.changed = sync.NewCond(&book.mu)
	book.inner = tcp.NewForwarder(engine.stack, 0, MaxTCPTuples, book.callback)
	return book
}
func (b *tcpBook) activate() { b.mu.Lock(); b.accepting = true; b.mu.Unlock() }
func (b *tcpBook) handlePacket(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.accepting || b.engine.transfer.ctx.Err() != nil {
		return true
	}
	if _, found := b.slots[id]; found {
		return true
	}
	if len(b.slots) >= MaxTCPTuples {
		return true
	}
	b.slots[id] = &tcpSlot{}
	// All inner inflight tuples originated here, and inner capacity equals outer
	// capacity. Thus true for a fresh tuple means one callback was scheduled.
	if !b.inner.HandlePacket(id, packet) {
		delete(b.slots, id)
		b.changed.Broadcast()
		return false
	}
	return true
}
func (b *tcpBook) callback(request *tcp.ForwarderRequest) {
	id := request.ID()
	b.mu.Lock()
	slot, ok := b.slots[id]
	if !ok || slot.claimed {
		b.fault = true
		b.mu.Unlock()
		request.Complete(true)
		b.engine.transfer.failure("TCP_OWNERSHIP")
		return
	}
	slot.claimed = true
	// Constructor admission and Add share Stop's exact mutex, so a delayed
	// callback cannot start construction after Stop observes a zero barrier.
	if !b.accepting || b.engine.transfer.ctx.Err() != nil {
		b.mu.Unlock()
		request.Complete(true)
		b.release(id)
		return
	}
	b.constructors++
	b.mu.Unlock()
	queue := &waiter.Queue{}
	callDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go cancellationWatcher(b.engine.transfer.ctx, queue, callDone, watcherDone)
	endpoint, err := request.CreateEndpoint(queue)
	close(callDone)
	<-watcherDone
	// The watcher is joined before queue reuse by gonet. Cancellation may race
	// successful construction; such an endpoint never enters forwarding.
	cancelled := b.engine.transfer.ctx.Err() != nil
	if err != nil || cancelled {
		if endpoint != nil {
			endpoint.Abort()
			endpoint.Close()
		}
		request.Complete(true)
		b.mu.Lock()
		b.constructors--
		b.changed.Broadcast()
		b.mu.Unlock()
		b.release(id)
		return
	}
	conn := gonet.NewTCPConn(queue, endpoint)
	request.Complete(false)
	b.mu.Lock()
	b.constructors--
	slot.forwarding = true
	b.changed.Broadcast()
	b.mu.Unlock()
	defer b.release(id)
	metadata := &C.Metadata{Type: C.TUN, NetWork: C.TCP, SrcIP: address(id.RemoteAddress), SrcPort: id.RemotePort, DstIP: address(id.LocalAddress), DstPort: id.LocalPort, RequestContext: b.engine.root}
	// root is the fixed marked context, never an arbitrary caller parent.
	b.engine.bound.HandleTCPConn(conn, metadata)
}
func cancellationWatcher(ctx context.Context, queue *waiter.Queue, callDone <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	select {
	case <-callDone:
		return
	case <-ctx.Done():
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-callDone:
			return
		default:
		}
		if queue.Events()&waiter.WritableEvents != 0 {
			queue.Notify(waiter.WritableEvents)
			return
		}
		select {
		case <-callDone:
			return
		case <-ticker.C:
		}
	}
}
func (b *tcpBook) release(id stack.TransportEndpointID) {
	b.mu.Lock()
	delete(b.slots, id)
	b.changed.Broadcast()
	b.mu.Unlock()
}
func (b *tcpBook) stopAdmission() {
	b.mu.Lock()
	b.accepting = false
	b.changed.Broadcast()
	b.mu.Unlock()
}
func (b *tcpBook) waitConstructions() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.constructors != 0 {
		b.changed.Wait()
	}
}
func (b *tcpBook) waitCallbacks() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.slots) != 0 {
		b.changed.Wait()
	}
}
func (b *tcpBook) isFault() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.fault }
func (b *tcpBook) counts() (callbacks, constructors, forwarding int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, slot := range b.slots {
		if slot.forwarding {
			forwarding++
		}
	}
	return len(b.slots), b.constructors, forwarding
}
