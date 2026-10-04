package outbound

import (
	"net"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// No packet I/O is performed by these construction/identity checks.
type egressPacketConn struct{ net.PacketConn }

func TestConnectionEgressSurvivesGroupsAndAdapterChanges(t *testing.T) {
	for _, kind := range []C.AdapterType{C.Direct, C.Compatible, C.Dns, C.Reject, C.Socks5, C.Shadowsocks} {
		t.Run(kind.String(), func(t *testing.T) {
			adapter := NewBase(BaseOption{Name: "DIRECT", Type: kind})
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			tcp := NewConn(left, adapter)
			udp := NewPacketConn(&egressPacketConn{}, adapter)
			group := NewBase(BaseOption{Name: "selection", Type: C.Selector})
			for _, connection := range []C.Connection{tcp, udp} {
				connection.AppendToChains(group)
				if connection.EgressType() != kind {
					t.Fatalf("group replaced established egress: %v", connection.EgressType())
				}
				if got := connection.Chains(); len(got) != 2 || got[0] != "DIRECT" || got[1] != "selection" {
					t.Fatalf("existing chains changed: %v", got)
				}
			}
			// A future selection/configuration cannot reclassify a live socket.
			adapter.tp = C.Http
			if tcp.EgressType() != kind || udp.EgressType() != kind {
				t.Fatal("egress identity was not frozen at connection construction")
			}
		})
	}
}
