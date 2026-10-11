package tunnel_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	"github.com/metacubex/mihomo/tunnel"
)

var originalRoutingGate protection.Gate
var originalRoutingHook sync.Once

func originalUDPPolicyRun(t *testing.T, rule string, sourceRouting bool) (C.Tunnel, uint64, *atomic.Int32) {
	t.Helper()
	owner, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	input := []byte("ipv6: false\ndns: {enable: false}\nproxies:\n - {name: udp-disabled-required, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: routing-fixture-only, udp: false}\nproxy-groups:\n - {name: original-required, type: select, proxies: [udp-disabled-required]}\nrules: [\"" + rule + "\"]\n")
	plan := owner.Plan("routing-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete {
		t.Fatalf("actual original routing input failed its pure plan: %s/%s", plan.Category, plan.Code)
	}
	platform := contract.Platform{RuntimeOptions: contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true}, PlatformPolicy: contract.PlatformPolicy{Revision: "routing-fixture-v1", AddressFamily: "ipv4", ApplicationIDs: []string{}}, TunPolicy: contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}}
	prepared, err := contract.Seal(plan.InputDigest, nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := owner.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { candidate.Discard(context.Background()) })
	originalRoutingHook.Do(func() {
		if originalRoutingGate.InstallDialerHook() != protection.Success {
			panic("routing fixture hook installation")
		}
	})
	id := generation.Add(1)
	protects := new(atomic.Int32)
	if originalRoutingGate.Register(id, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success }) != protection.Success {
		t.Fatal("routing fixture actual gate registration")
	}
	t.Cleanup(func() {
		if originalRoutingGate.Unregister(id) != protection.Success {
			t.Error("routing fixture retained a physical protection callback after stop")
		}
	})
	root := protection.WithGeneration(context.Background(), id)
	if sourceRouting {
		root = tunnel.WithMobilePolicyRouting(root)
	}
	tunnel.EnableForwardingLifecycle()
	if err = tunnel.PrepareForwarding(root, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopRun(t) })
	bound, err := tunnel.BoundForwardingTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = candidate.ActivateMobileNetwork(id); err != nil {
		t.Fatal(err)
	}
	if err = executor.PublishMobilePolicy(root, candidate); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopRun(t)
		if err := executor.RetireConfig(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err = tunnel.ActivateForwarding(id); err != nil {
		t.Fatal(err)
	}
	if err = executor.ActivateMobilePolicy(candidate); err != nil {
		t.Fatal(err)
	}
	return bound, id, protects
}

func TestBoundMobileOriginalRequiredUDPDoesNotImplicitlyGoDirect(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	bound, _, protects := originalUDPPolicyRun(t, "MATCH,original-required", true)
	packet := &flowPacket{completed: make(chan error, 2)}
	address := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: packet.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), SrcPort: 51341, DstIP: address.Addr(), DstPort: address.Port()})
	_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, _, err := peer.ReadFrom(make([]byte, 128)); err == nil {
		t.Fatalf("the original required UDP-disabled node silently sent %d bytes through actual DIRECT", n)
	}
	stopRun(t)
	if err = await(t, packet.completed); err != nil || packet.retained.Load() != 1 || packet.drops.Load() != 1 || !packet.closing.Load() || protects.Load() != 0 {
		t.Fatal("rejected original UDP policy did not close its real packet/flow lease exactly once before any physical dial")
	}
}

func TestBoundMobileDeclaredDirectAndUnmarkedFallbackStillReachActualPeer(t *testing.T) {
	for _, fixture := range []struct {
		name, rule string
		marked     bool
	}{
		{"original-declared-direct", "MATCH,DIRECT", true},
		{"unmarked-legacy-fallback", "MATCH,original-required", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			bound, _, protects := originalUDPPolicyRun(t, fixture.rule, fixture.marked)
			packet := &flowPacket{completed: make(chan error, 2)}
			address := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: packet.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), SrcPort: 51341, DstIP: address.Addr(), DstPort: address.Port()})
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 128)
			if n, _, err := peer.ReadFrom(buffer); err != nil || string(buffer[:n]) != "client-udp-buffer" {
				t.Fatalf("declared DIRECT/unmarked upstream behavior did not reach the actual peer: %v", err)
			}
			stopRun(t)
			if err = await(t, packet.completed); err != nil || packet.drops.Load() != 1 || packet.retained.Load() != 1 || protects.Load() == 0 {
				t.Fatal("actual allowed UDP flow did not retain its physical lifetime through normal stop")
			}
		})
	}
}

func TestMobileSharedDNSRespectRulesRetainsActualOriginalRunMarker(t *testing.T) {
	_, id, protects := originalUDPPolicyRun(t, "MATCH,original-required", true)
	scope, err := forwarding.Context(id)
	if err != nil {
		t.Fatal(err)
	}
	shared := forwarding.SharedManagementNetworkContext(scope)
	if forwarding.Generation(shared) != 0 || protection.Generation(shared) != id {
		t.Fatal("actual shared DNS context did not detach only the individual forwarding owner")
	}
	dialer := tunnel.NewDNSDialer(resolver.SystemResolver, nil, tunnel.DnsRespectRules)
	if conn, err := dialer.DialContext(shared, "udp4", "127.0.0.1:53"); conn != nil || !errors.Is(err, tunnel.ErrMobilePolicyUDPUnsupported) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("actual shared DNS DialContext escaped the original UDP rule: %v", err)
	}
	if conn, err := dialer.ListenPacket(shared, "udp4", "127.0.0.1:53"); conn != nil || !errors.Is(err, tunnel.ErrMobilePolicyUDPUnsupported) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("actual shared DNS ListenPacket escaped the original UDP rule: %v", err)
	}
	if protects.Load() != 0 {
		t.Fatal("shared DNS selected an undeclared physical route before reporting the fixed policy error")
	}
}

func TestBoundMobileOriginalRunRejectsChangedProtectionGeneration(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	bound, id, protects := originalUDPPolicyRun(t, "MATCH,DIRECT", true)
	scope, err := forwarding.Context(id)
	if err != nil {
		t.Fatal(err)
	}
	packet := &flowPacket{completed: make(chan error, 2)}
	address := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: packet.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), SrcPort: 51341, DstIP: address.Addr(), DstPort: address.Port(), RequestContext: protection.WithGeneration(scope, id+1)})
	_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err = peer.ReadFrom(make([]byte, 128)); err == nil {
		t.Fatal("changed protection identity was accepted by the original policy run")
	}
	stopRun(t)
	if err = await(t, packet.completed); err != nil || packet.drops.Load() != 1 || packet.retained.Load() != 1 || protects.Load() != 0 {
		t.Fatal("invalid policy context did not finish its rejected packet before any physical socket")
	}
}
