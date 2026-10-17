//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"testing"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

// This is the same serialization boundary as the runtime C exports. Empty
// identities remain required strings so the native and application consumers
// can observe absence, rejection and normal stop without inventing identity.
func TestActualRuntimeReceiptsKeepAllIdentityFieldsOnWire(t *testing.T) {
	check := func(name string, receipt R.Receipt) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("RUNTIME_WIRE_RECEIPT:%s", encoded)
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"inputDigest", "resourceManifestDigest", "platformPolicyDigest", "groupPreferencesDigest"} {
				var value string
				field, present := fields[name]
				if !present || json.Unmarshal(field, &value) != nil {
					t.Errorf("actual runtime wire receipt omitted required string %s", name)
				}
			}
		})
	}

	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	manager := R.NewManager(newPacketDescriptors(), &productionGate)
	t.Cleanup(func() { manager.Stop(generation) })
	check("absent-query", manager.Query(generation, 1))
	check("absent-stop", manager.Stop(generation))
	started := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	if started.Outcome != "running" || !started.ForwardingActive || started.InputDigest == "" || started.PlatformPolicyDigest == "" || started.ResourceManifestDigest != "" || started.GroupPreferencesDigest != "" {
		t.Fatalf("actual selected-node candidate did not establish its distinct identity: %+v", started)
	}
	check("selected-node-start", started)
	check("selected-node-query", manager.Query(generation, 1))
	stopped := manager.Stop(generation)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("actual selected-node stop did not complete: %+v", stopped)
	}
	check("selected-node-stop", stopped)
	check("selected-node-stopped-query", manager.Query(generation, 1))

	failedGeneration := nextGeneration()
	failedManager := R.NewManager(newDescriptors())
	check("failed-start", failedManager.Start(failedManager.Consume(failedGeneration, 1, 9), fixed, []byte("{}")))
	failed := failedManager.Stop(failedGeneration)
	if failed.Phase != "failed" || failed.FailureCode == "" || failed.Cleanup != "complete" {
		t.Fatalf("actual invalid request did not finish owned cleanup: %+v", failed)
	}
	check("failed-stop", failed)
	check("failed-query", failedManager.Query(failedGeneration, 1))

	policyGeneration := nextGeneration()
	register(policyGeneration, func(uint64, uint64, uintptr) int32 { return protection.Success })
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policyManager := R.NewManagerWithPolicy(newPacketDescriptors(), &productionGate, owner)
	t.Cleanup(func() { policyManager.Stop(policyGeneration); owner.Close() })
	networkGeneration := publishClientNetwork(t, policyManager)
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['MATCH,REJECT']\n")
	policyStarted := policyManager.Start(policyManager.Consume(policyGeneration, 1, 9), input, clientPolicyRequest(t, input, policyGeneration, networkGeneration, false, false))
	if policyStarted.Outcome != "running" || policyStarted.InputDigest == "" || policyStarted.ResourceManifestDigest == "" || policyStarted.PlatformPolicyDigest == "" || policyStarted.GroupPreferencesDigest == "" {
		t.Fatalf("actual original policy did not establish all four identities: %+v", policyStarted)
	}
	check("source-policy-start", policyStarted)
	check("source-policy-query", policyManager.Query(policyGeneration, 1))
	policyStopped := policyManager.Stop(policyGeneration)
	if policyStopped.Phase != "stopped" || policyStopped.Cleanup != "complete" || policyStopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("actual original policy stop did not complete: %+v", policyStopped)
	}
	check("source-policy-stop", policyStopped)
}
