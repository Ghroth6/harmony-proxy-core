//go:build with_gvisor

package runtime_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"go.yaml.in/yaml/v3"
)

// Core runtime fixtures use canonical nodes. Application import integration is
// covered by the application nativecore tests, without a reverse dependency.
func composeInspectedNode(t *testing.T, original []byte) ([]byte, string) {
	t.Helper()
	var source struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(original, &source); err != nil || len(source.Proxies) != 1 {
		t.Fatal("invalid node fixture")
	}
	source.Proxies[0]["name"] = "selected-node"
	node, err := json.Marshal(source.Proxies[0])
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("proxies:\n  - " + string(node) + "\nproxy-groups:\n  - name: selected\n    type: select\n    proxies: [\"selected-node\"]\nrules:\n  - MATCH,selected\n")
	return input, contract.Digest(original)
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
			if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Requirements) != 0 || !plan.GeneralIPv6 || plan.DNSEnabled || plan.InputDigest == inspected {
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
