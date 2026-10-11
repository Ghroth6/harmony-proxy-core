//go:build with_gvisor

package runtime

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

// All helpers are called by the single runtime owner. Configuration never
// activates ingress, performs DNS, or opens a physical socket.
func (e *runEngine) configurePacketStack(target StartRequest) string {
	e.options = target.RuntimeOptions
	e.sourcePolicy = target.PreparedPolicy != nil
	if e.options.DNS {
		if e.cfg.MobileDNSService() == nil {
			return "DNS_SERVICE_NOT_READY"
		}
		e.dns = newDNSBook(e, e.cfg.MobileDNSService())
	}
	e.endpoint = channel.New(PacketQueue, MTU, "")
	networks := []stack.NetworkProtocolFactory{ipv4.NewProtocol}
	transports := []stack.TransportProtocolFactory{tcp.NewProtocol}
	routes := []tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}}
	if e.options.IPv6 {
		networks = append(networks, ipv6.NewProtocol)
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	if e.options.UDP {
		transports = append(transports, udp.NewProtocol)
	}
	e.stack = stack.New(stack.Options{NetworkProtocols: networks, TransportProtocols: transports})
	e.transfer.resource("packet-stack", "acquired", -1)
	e.book = newTCPBook(e)
	e.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, e.book.handlePacket)
	if e.options.UDP {
		e.udp = newUDPBook(e)
		e.stack.SetTransportProtocolHandler(udp.ProtocolNumber, e.udp.handlePacket)
	}
	if err := e.stack.CreateNICWithOptions(1, e.endpoint, stack.NICOptions{}); err != nil {
		return "STACK_NIC"
	}
	e.stack.SetRouteTable(routes)
	if e.stack.SetSpoofing(1, true) != nil || e.stack.SetPromiscuousMode(1, true) != nil {
		return "STACK_OPTIONS"
	}
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
