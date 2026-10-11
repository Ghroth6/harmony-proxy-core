package tunnel

import (
	"errors"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

type udpFlowOwner struct {
	closing  func()
	finished func(error)
	close    sync.Once
	finish   sync.Once
	mu       sync.Mutex
	closeErr error
}

func retainUDPFlow(packet C.UDPPacket) (*udpFlowOwner, bool) {
	if retainer, ok := packet.(C.UDPFlowOwner); ok {
		closing, finished, admitted := retainer.RetainUDPFlow()
		if !admitted {
			return nil, false
		}
		if closing != nil || finished != nil {
			return &udpFlowOwner{closing: closing, finished: finished}, true
		}
	}
	return nil, true
}

func (o *udpFlowOwner) closeAdmission() {
	if o == nil {
		return
	}
	o.close.Do(func() {
		if o.closing != nil {
			o.closing()
		}
	})
}

func (o *udpFlowOwner) complete(err error) {
	if o == nil {
		return
	}
	o.closeAdmission()
	o.finish.Do(func() {
		o.mu.Lock()
		err = errors.Join(err, o.closeErr)
		o.mu.Unlock()
		if o.finished != nil {
			o.finished(err)
		}
	})
}

// This wrapper is created before OwnUDP so even a late rejected physical
// result has one synchronous Close barrier. The forwarding owner and this
// caller can race Close without releasing the flow before the real call ends.
type udpFlowPacketConn struct {
	C.PacketConn
	flow *udpFlowOwner
	once sync.Once
	err  error
}

func (c *udpFlowPacketConn) Close() error {
	c.once.Do(func() {
		c.flow.closeAdmission()
		c.err = c.PacketConn.Close()
		c.flow.mu.Lock()
		c.flow.closeErr = errors.Join(c.flow.closeErr, c.err)
		c.flow.mu.Unlock()
	})
	return c.err
}

func (c *udpFlowPacketConn) Upstream() any { return c.PacketConn }
