package dialer

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/platformnetwork"
)

func TestUnknownPlatformIndexCannotBind(t *testing.T) {
	if err := platformnetwork.Publish(platformnetwork.Snapshot{Generation: 1, Online: true, Interfaces: []platformnetwork.Interface{{Name: "unknown-index", Up: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := bindIfaceToDialer("unknown-index", &net.Dialer{}, "tcp", netip.MustParseAddr("192.0.2.1")); !errors.Is(err, iface.ErrIndexUnknown) {
		t.Fatalf("dial bind: %v", err)
	}
	if _, err := bindIfaceToListenConfig("unknown-index", &net.ListenConfig{}, "udp", ":0", netip.AddrPort{}); !errors.Is(err, iface.ErrIndexUnknown) {
		t.Fatalf("listen bind: %v", err)
	}
}
