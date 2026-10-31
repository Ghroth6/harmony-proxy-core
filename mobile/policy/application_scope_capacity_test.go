package policy_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

// The host validates the actual application/core wire and candidate construction.
// A successful core check does not claim that a target OS accepts this list size.
func TestApplicationScopeCapacityBelongsToPlatform(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	input := []byte(noResourcePolicy)
	for _, count := range []int{17, 64, 65, 256, 257} {
		for _, scope := range []string{"include", "legacy"} {
			t.Run(fmt.Sprintf("%s-%d", scope, count), func(t *testing.T) {
				platform := publicPlatform()
				ids := make([]string, count)
				for index := range ids {
					ids[index] = fmt.Sprintf("org.example.application%d", index)
				}
				ids[0] = "com.example.123app"
				ids[1] = "com." + strings.Repeat("a.", 15) + "last"
				ids[2] = "platform_identifier"
				platform.PlatformPolicy.ApplicationIDs = ids
				if scope == "include" {
					platform.PlatformPolicy.ApplicationScope = &scope
				}
				prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(prepared)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := engine.ValidateJSON("scope-capacity", input, encoded)
				if err != nil || receipt.Category != "pass" || receipt.CandidateDigest != prepared.CandidateDigest {
					t.Fatalf("valid list rejected before reaching the platform: %v %s/%s", err, receipt.Category, receipt.Code)
				}
				request := R.StartRequest{ContractVersion: R.ContractVersion, OperationID: "scope-capacity",
					Generation: 2, NetworkGeneration: 1, TransferID: "7", InputRevision: "scope-capacity-1",
					InputDigest: prepared.InputDigest, RuntimeOptions: platform.RuntimeOptions,
					PlatformPolicy: platform.PlatformPolicy, TunPolicy: platform.TunPolicy, PreparedPolicy: &prepared}
				wire, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := R.DecodeStart(2, 7, input, wire)
				if err != nil || !slices.Equal(decoded.PlatformPolicy.ApplicationIDs, ids) ||
					!slices.Equal(decoded.PreparedPolicy.Platform.PlatformPolicy.ApplicationIDs, ids) {
					t.Fatalf("runtime truncated or rejected the accepted list: %v", err)
				}
				if (decoded.PlatformPolicy.ApplicationScope == nil) != (scope == "legacy") {
					t.Fatal("legacy scope identity changed")
				}
			})
		}
	}
}
