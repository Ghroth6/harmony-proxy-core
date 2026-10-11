package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestPolicyWireRejectsAmbiguousFieldsBeforeTypedPreparation(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte(noResourcePolicy)
	plan, err := engine.PlanJSON("wire-plan", input, []byte("[]"))
	if err != nil || plan.Category != "planned" {
		t.Fatal("bounded exact resource array must enter the real planner")
	}
	for _, text := range []string{"null", "[null]", "{}", "[] []", `[{"refId":"documentation","refId":"duplicate"}]`, `[{"refId":"documentation","extra":true}]`} {
		if _, err := engine.PlanJSON("wire-negative", input, []byte(text)); err == nil {
			t.Fatal("resource wire must reject null, duplicate, unknown, missing or trailing values")
		}
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	positive, err := engine.ValidateJSON("wire-validation", input, encoded)
	if err != nil || positive.Category != "pass" {
		t.Fatal("exact typed context must reach real candidate construction/cleanup")
	}
	for _, text := range []string{strings.Replace(string(encoded), `"udp":true,`, "", 1), strings.Replace(string(encoded), `"resources":[]`, `"resources":null`, 1), strings.Replace(string(encoded), `"dns":false`, `"dns":false,"dns":false`, 1), strings.Replace(string(encoded), `"dns":false`, `"dns":false,"extra":0`, 1), strings.Replace(string(encoded), `"revision":"public-policy-v1"`, `"revision":"\ud800"`, 1)} {
		if _, err := engine.ValidateJSON("wire-invalid", input, []byte(text)); err == nil {
			t.Fatal("context must not infer missing false values or discard ambiguous nested fields")
		}
	}
}
