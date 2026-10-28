//go:build with_gvisor

package runtime

import (
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	tun "github.com/metacubex/sing-tun"
)

// All helpers are called by the single runtime owner. Configuration never
// activates ingress, performs DNS, or opens a physical socket.
func (e *runEngine) configurePacketStack(target StartRequest) string {
	e.options = target.RuntimeOptions
	if e.options.DNS {
		if e.cfg.MobileDNSService() == nil {
			return "DNS_SERVICE_NOT_READY"
		}
		e.dns = newDNSBook(e, e.cfg.MobileDNSService())
	}
	e.endpoint = channel.New(PacketQueue, MTU, "")
	// Use the public upstream constructor while retaining the stack handle needed
	// to join its workers. The OHOS fd/poll owner supplies packets through channel;
	// it never enters fdbased.New's mandatory fd metadata probe.
	var err error
	e.stack, err = tun.NewGVisorStack(e.endpoint)
	if err != nil {
		return "STACK_NIC"
	}
	e.transfer.resource("packet-stack", "acquired", -1)
	e.book = newTCPBook(e)
	e.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, e.book.handlePacket)
	if e.options.UDP {
		e.udp = newUDPBook(e)
		e.stack.SetTransportProtocolHandler(udp.ProtocolNumber, e.udp.handlePacket)
	} else {
		e.stack.SetTransportProtocolHandler(udp.ProtocolNumber, discardTransportPacket)
	}
	// ICMP forwarding is not part of the current accepted mobile contract.
	e.stack.SetTransportProtocolHandler(icmp.ProtocolNumber4, discardTransportPacket)
	e.stack.SetTransportProtocolHandler(icmp.ProtocolNumber6, discardTransportPacket)
	e.transfer.mu.Lock()
	if e.options.UDP {
		e.transfer.receipt.Stack = "gvisor-ipv4-tcp-udp"
		if e.options.IPv6 {
			e.transfer.receipt.Stack = "gvisor-dual-tcp-udp"
		}
	}
	e.transfer.mu.Unlock()
	return ""
}

func discardTransportPacket(stack.TransportEndpointID, *stack.PacketBuffer) bool { return true }

func (e *runEngine) activateClientIngress() {
	if e.book != nil {
		e.book.activate()
	}
	if e.udp != nil {
		e.udp.activate()
	}
	if e.dns != nil {
		e.dns.activate()
	}
}

func (e *runEngine) stopClientIngress() {
	if e.book != nil {
		e.book.stopAdmission()
	}
	if e.udp != nil {
		e.udp.stopAdmission()
	}
	if e.dns != nil {
		e.dns.stopAdmission()
	}
}

func (e *runEngine) waitClientIngress() bool {
	fault := false
	if e.dns != nil {
		e.dns.wait()
		fault = e.dns.isFault()
	}
	if e.udp != nil {
		e.udp.wait()
		fault = fault || e.udp.isFault()
	}
	return fault
}
