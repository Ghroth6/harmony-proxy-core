package iface

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/platformnetwork"
)

func TestPlatformInterfacesReplaceNativeCacheImmediately(t *testing.T) {
	// Warm the native cache first: publishing must bypass it immediately.
	_, _ = Interfaces()
	snapshot := platformnetwork.Snapshot{Generation: 1, NetworkID: 900, Online: true,
		Interfaces: []platformnetwork.Interface{{Name: "no-such-host-interface", MTU: 1400, Up: true,
			Addresses: []string{"192.0.2.9/24", "2001:db8:1::9/64"},
			Routes:    []platformnetwork.Route{{Destination: "198.51.100.0/24"}},
		}},
	}
	if err := platformnetwork.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.9", "192.0.2.99", "2001:db8:1::9", "2001:db8:1::99", "198.51.100.25"} {
		got, err := ResolveInterfaceByAddr(netip.MustParseAddr(address))
		if err != nil || got.Name != "no-such-host-interface" {
			t.Fatalf("%s: %+v %v", address, got, err)
		}
		if got.Index != 0 {
			t.Fatal("network id was treated as interface index")
		}
	}
	for _, tc := range []struct {
		ip    string
		local bool
	}{{"192.0.2.9", true}, {"2001:db8:1::9", true}, {"192.0.2.99", false}, {"198.51.100.25", false}} {
		got, err := IsLocalIp(netip.MustParseAddr(tc.ip))
		if err != nil || got != tc.local {
			t.Fatalf("local %s: %v %v", tc.ip, got, err)
		}
	}
	first, _ := ResolveInterface("no-such-host-interface")
	first.Addresses[0] = netip.MustParsePrefix("203.0.113.7/24")
	first.Name = "modified"
	second, _ := ResolveInterface("no-such-host-interface")
	if second.Name != "no-such-host-interface" || second.Addresses[0].Addr().String() != "192.0.2.9" {
		t.Fatal("returned interface aliases published state")
	}
	snapshot.Generation++
	snapshot.Interfaces[0].Addresses = []string{"203.0.113.9/24"}
	snapshot.Interfaces[0].Routes = nil
	if err := platformnetwork.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveInterfaceByAddr(netip.MustParseAddr("192.0.2.9")); !errors.Is(err, ErrIfaceNotFound) {
		t.Fatalf("old address cached: %v", err)
	}
	if _, err := ResolveInterfaceByAddr(netip.MustParseAddr("203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if err := platformnetwork.Publish(platformnetwork.Snapshot{Generation: 3}); err != nil {
		t.Fatal(err)
	}
	if got, err := Interfaces(); err != nil || len(got) != 0 {
		t.Fatalf("offline enumerated host: %+v %v", got, err)
	}
}
