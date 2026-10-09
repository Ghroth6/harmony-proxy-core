// Package protection owns the mobile socket-protection admission gate.
package protection

import (
	"fmt"
	"sync"
	"syscall"
)

const (
	Success int32 = iota
	Invalid
	Inactive
	Busy
	Failed
	QueueFull
	Cancelled
	Timeout
	EnvironmentInvalid
	PlatformFailure
	CleanupUnknown
)

// Callback may only borrow fd during the call. It must duplicate before queuing
// asynchronous work and must bound its wait. Nonzero always forbids connecting.
type Callback func(generation, requestID uint64, fd uintptr) int32

// Gate's zero value rejects protection. Its registration owns the callback until
// Unregister returns Success; Busy has already closed admission.
type Gate struct {
	mu           sync.Mutex
	generation   uint64
	callback     Callback
	accepting    bool
	active       map[uint64]bool
	nextRequest  uint64
	observations []ProbeReceipt
}

// Ready is a read-only readiness check for a fixed mobile run before opening
// packet admission. It does not perform a probe or change callback ownership.
func (g *Gate) Ready(generation uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return generation != 0 && g.generation == generation && g.accepting && g.callback != nil
}

// ProbeReceipt contains local observations, not platform-protection evidence.
// -1 means unavailable; descriptor numbers alone never prove socket identity.
type ProbeReceipt struct {
	Generation, RequestID                      uint64
	SocketIdentity                             int64
	BeforeSocket, AfterSameSocket, CloseResult int32
}

// Error deliberately contains only the status, never the destination or input.
type Error struct{ Code int32 }

func (e Error) Error() string { return fmt.Sprintf("socket protection failed (%d)", e.Code) }

// Scalar classification for the mobile safe log boundary; no raw error text.
func (e Error) MobileProtectionStatus() int32 { return e.Code }

// SocketControl is installed once at mobile process initialization. Registration
// changes are synchronized inside Gate; the engine's global hook is never reset.
func (g *Gate) SocketControl(network, address string, conn syscall.RawConn) error {
	g.mu.Lock()
	generation := g.generation
	g.mu.Unlock()
	return g.socketControl(generation, network, address, conn)
}

func (g *Gate) socketControl(generation uint64, _, _ string, conn syscall.RawConn) error {
	g.mu.Lock()
	if !g.accepting || generation != g.generation || generation == 0 {
		g.mu.Unlock()
		return Error{Inactive}
	}
	if g.nextRequest == 0x7fffffffffffffff {
		g.mu.Unlock()
		return Error{Failed}
	}
	g.nextRequest++
	request := g.nextRequest | 0x8000000000000000
	g.mu.Unlock()
	if status := g.ProtectSocket(generation, request, conn); status != Success {
		return Error{status}
	}
	return nil
}

func (g *Gate) Register(generation uint64, callback Callback) int32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if generation == 0 || generation > 0x7fffffff || callback == nil {
		return Invalid
	}
	if g.callback != nil {
		return Busy
	}
	if generation <= g.generation {
		return Invalid
	}
	g.generation, g.callback, g.accepting = generation, callback, true
	g.active = make(map[uint64]bool)
	g.observations = nil
	return Success
}

func (g *Gate) Unregister(generation uint64) int32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if generation == 0 || generation != g.generation {
		return Inactive
	}
	g.accepting = false
	if len(g.active) != 0 {
		return Busy
	}
	g.callback = nil
	return Success
}

// ProtectSocket enters RawConn.Control so the original socket cannot be closed
// or reused while the callback duplicates it. It never closes the original.
func (g *Gate) ProtectSocket(generation, requestID uint64, conn syscall.RawConn) (status int32) {
	if generation == 0 || requestID == 0 || conn == nil {
		return Invalid
	}
	g.mu.Lock()
	if !g.accepting || generation != g.generation {
		g.mu.Unlock()
		return Inactive
	}
	if g.active[requestID] {
		g.mu.Unlock()
		return Busy
	}
	callback := g.callback
	g.active[requestID] = true
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.active, requestID)
		if status == Success && !g.accepting {
			status = Inactive
		}
		g.mu.Unlock()
		if recover() != nil {
			status = Failed
		}
	}()
	status = Failed
	err := conn.Control(func(fd uintptr) { status = callback(generation, requestID, fd) })
	if err != nil {
		return Failed
	}
	if status < Success || status > CleanupUnknown {
		return Failed
	}
	return status
}

// Probe is test-only orchestration of the production protection path. It makes
// one unconnected IPv4 TCP socket, never binds/connects/sends, and closes it.
func (g *Gate) Probe(generation, requestID uint64) int32 {
	if requestID == 0 || requestID > 0x7fffffffffffffff {
		return Invalid
	}
	conn, closeSocket, err := openProbeSocket()
	if err != nil {
		return Failed
	}
	identity, before := observeProbeSocket(conn)
	status := g.ProtectSocket(generation, requestID, conn)
	closeResult := Success
	if closeSocket() != nil {
		closeResult = CleanupUnknown
		status = CleanupUnknown
	}
	receipt := ProbeReceipt{generation, requestID, identity.public, before,
		observeSameProbeSocket(conn, identity), closeResult}
	g.mu.Lock()
	if generation == g.generation {
		if len(g.observations) == 32 {
			g.observations = g.observations[1:]
		}
		g.observations = append(g.observations, receipt)
	}
	g.mu.Unlock()
	return status
}

// ProbeObservation returns at most the latest 32 completed probes, including
// after unregister. A later registration discards the earlier generation.
func (g *Gate) ProbeObservation(generation, requestID uint64) (ProbeReceipt, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.observations) - 1; i >= 0; i-- {
		if receipt := g.observations[i]; receipt.Generation == generation && receipt.RequestID == requestID {
			return receipt, true
		}
	}
	return ProbeReceipt{}, false
}
