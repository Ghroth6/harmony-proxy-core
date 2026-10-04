package outbound_test

import (
	"encoding/base64"
	"runtime"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	_ "github.com/metacubex/mihomo/config" // Installs the real DNS configuration parser.
)

func wireGuardWorkers() int {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "github.com/metacubex/wireguard-go/device.(*Device).Routine")
}

func TestWireGuardRejectedDNSDoesNotRetainDevice(t *testing.T) {
	baseline := wireGuardWorkers()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for attempt := 0; attempt < 3; attempt++ {
		proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
			Name: "candidate", Ip: "10.0.0.2/32", PrivateKey: key, Workers: 1,
			WireGuardPeerOption: outbound.WireGuardPeerOption{
				Server: "127.0.0.1", Port: 51820, PublicKey: key,
			},
			RemoteDnsResolve: true, Dns: []string{"invalid-scheme://127.0.0.1"},
		})
		if err == nil || proxy != nil {
			if proxy != nil {
				_ = proxy.Close()
			}
			t.Fatalf("invalid DNS returned proxy=%v err=%v", proxy, err)
		}
		if got := wireGuardWorkers(); got != baseline {
			t.Fatalf("rejected constructor retained WireGuard workers: got %d, baseline %d", got, baseline)
		}
	}
}

func TestWireGuardAcceptedCandidateOwnsDeviceUntilClose(t *testing.T) {
	baseline := wireGuardWorkers()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name: "candidate", Ip: "10.0.0.2/32", PrivateKey: key, Workers: 1,
		WireGuardPeerOption: outbound.WireGuardPeerOption{
			Server: "127.0.0.1", Port: 51820, PublicKey: key,
		},
		RemoteDnsResolve: true, Dns: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	if got := wireGuardWorkers(); got <= baseline {
		t.Fatalf("accepted device has no WireGuard workers: got %d, baseline %d", got, baseline)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if got := wireGuardWorkers(); got != baseline {
		t.Fatalf("closed device retained WireGuard workers: got %d, baseline %d", got, baseline)
	}
}
