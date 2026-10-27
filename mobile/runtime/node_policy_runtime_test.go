//go:build with_gvisor

package runtime_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/mobile/content"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

// Production composes the inspector's canonical JSON with this saved base.
// Neither component supplies a hidden IPv6 or DNS setting.
func composeInspectedNode(t *testing.T, original []byte) ([]byte, content.Receipt) {
	t.Helper()
	inspected := content.Inspect("public-node-inspection", original)
	if len(inspected.Entries) != 1 || inspected.Entries[0].Status != "supported" {
		t.Fatalf("public node inspection failed: %+v", inspected)
	}
	input := []byte("proxies:\n  - " + inspected.Entries[0].NodeJSON + "\nproxy-groups:\n  - name: selected\n    type: select\n    proxies: [\"selected-node\"]\nrules:\n  - MATCH,selected\n")
	return input, inspected
}

func TestComposedNodesUsePreparedPolicyDefaultsAndJoinedRuntime(t *testing.T) {
	for _, node := range []struct {
		name, fields string
		udp          bool
	}{
		{"ss-aes", "type: ss, cipher: aes-128-gcm, password: public-fixture, udp: true", true},
		{"ss-chacha", "type: ss, cipher: chacha20-ietf-poly1305, password: public-fixture, udp: true", true},
		{"trojan", "type: trojan, password: public-fixture, sni: node.example.invalid", false},
		{"trojan-udp", "type: trojan, password: public-fixture, sni: node.example.invalid, udp: true", true},
		{"socks5", "type: socks5, udp: true", true},
		{"http-tcp-only", "type: http", false},
	} {
		t.Run(node.name, func(t *testing.T) {
			original := []byte(fmt.Sprintf("proxies:\n  - {name: public-source-node, server: 127.0.0.1, port: 9, %s}\n", node.fields))
			input, inspected := composeInspectedNode(t, original)
			owner, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			generation := nextGeneration()
			var protected atomic.Int32
			register(generation, func(uint64, uint64, uintptr) int32 { protected.Add(1); return protection.Success })
			system := newPacketDescriptors()
			manager := R.NewManagerWithPolicy(system, &productionGate, owner)
			t.Cleanup(func() {
				manager.Stop(generation)
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			baseline := owner.ResourceAcquireCount()
			plan := owner.Plan("public-node-plan", input, nil)
			if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Requirements) != 0 || !plan.GeneralIPv6 || plan.DNSEnabled || plan.InputDigest == inspected.InputDigest {
				t.Fatalf("composed identity and upstream IPv6/DNS defaults changed: %+v", plan)
			}
			networkGeneration := publishClientNetwork(t, manager)
			var request R.StartRequest
			if err := json.Unmarshal(clientPolicyRequest(t, input, generation, networkGeneration, false, true), &request); err != nil {
				t.Fatal(err)
			}
			prepared, err := contract.Seal(plan.InputDigest, nil, request.PreparedPolicy.Platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.PreparedPolicy = &prepared
			validated := owner.Validate("public-node-validate", input, prepared)
			if validated.Category != "pass" || validated.CandidateDigest != prepared.CandidateDigest || owner.ResourceAcquireCount() != baseline || protected.Load() != 0 {
				t.Fatalf("node preparation acquired network or lost identity: %+v", validated)
			}
			first, err := owner.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			second, err := owner.BuildCandidate(input, prepared)
			if err != nil {
				_ = first.Discard(context.Background())
				t.Fatal(err)
			}
			if first.SharesCandidate(second) || first.Proxies["selected-node"] == second.Proxies["selected-node"] || !first.General.IPv6 || (first.DNS != nil && first.DNS.Enable) || first.Proxies["selected-node"].SupportUDP() != node.udp || len(first.Rules) != 1 || first.Rules[0].Adapter() != "selected" {
				t.Error("node policy construction changed semantics or reused owned adapters")
			}
			if err := first.Discard(context.Background()); err != nil {
				t.Error(err)
			}
			if second.CheckCandidate() != nil {
				t.Error("discard retired another candidate")
			}
			if err := second.Discard(context.Background()); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			started := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
			if started.Outcome != "running" || started.Stack != "gvisor-dual-tcp-udp" || started.NetworkGeneration != networkGeneration || started.InputDigest != plan.InputDigest || started.CandidateDigest != prepared.CandidateDigest || started.ResourceManifestDigest != prepared.ResourceManifestDigest || started.PlatformPolicyDigest != prepared.PlatformPolicyDigest || started.GroupPreferencesDigest != prepared.GroupPreferencesDigest || owner.ResourceAcquireCount() != baseline || protected.Load() != 0 {
				t.Fatalf("composed node did not enter common prepared runtime: %+v", started)
			}
			if !node.udp {
				peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				system.inject(clientUDP4Packet(peer.LocalAddr(), 51233, []byte("must-not-fall-back-direct")))
				_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				if _, _, err := peer.ReadFrom(make([]byte, 128)); err == nil {
					t.Fatal("TCP-only composed node silently sent UDP through DIRECT")
				}
				if protected.Load() != 0 || len(manager.Query(generation, 1).Connections) != 0 {
					t.Fatal("unsupported node UDP opened a physical route or published a successful connection")
				}
			}
			stopped := manager.Stop(generation)
			if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
				t.Fatalf("node policy owners did not join: %+v", stopped)
			}
			for _, fd := range []int{9, 40, 41} {
				if system.closes[fd] != 1 {
					t.Errorf("descriptor %d close count %d", fd, system.closes[fd])
				}
			}
			fixture, err := json.Marshal(map[string]any{"originalInput": string(original), "composedInput": string(input), "inspection": inspected, "plan": plan, "validation": validated, "request": request, "start": started, "stop": stopped})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("NODE_POLICY_FIXTURE:%s", fixture)
		})
	}
}
