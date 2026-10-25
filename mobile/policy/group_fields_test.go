package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestOriginalGroupRejectsActualUpstreamDecodeAndDurationErrors(t *testing.T) {
	for _, field := range []string{"default-selected: [DIRECT]", "lazy: documentation", "interval: -1"} {
		t.Run(strings.Split(field, ":")[0]+"/"+strings.Split(field, ":")[1], func(t *testing.T) {
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			raw := []byte("ipv6: false\ndns: {enable: false}\nproxy-groups:\n - {name: PublicSelect, type: select, proxies: [REJECT, DIRECT], " + field + "}\nrules: ['MATCH,PublicSelect']\n")
			plan := engine.Plan("group-fields", raw, nil)
			if plan.Category == "planned" || plan.Code == "" {
				t.Fatal("declared group semantics must be explicitly rejected, never ignored")
			}
			prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if result := engine.Validate("group-fields-validate", raw, prepared); result.Category == "pass" || result.Code != plan.Code {
				t.Fatal("validation must preserve the same refusal")
			}
			candidate, err := engine.BuildCandidate(raw, prepared)
			if candidate != nil {
				_ = candidate.Discard(context.Background())
			}
			if candidate != nil || err == nil || err.Error() != plan.Code {
				t.Fatal("independent runtime construction must preserve the same refusal")
			}
		})
	}
}

func TestOriginalGroupSupportedFieldsAndMemberOrderArePreserved(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	raw := []byte(`ipv6: false
dns: {enable: false}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [REJECT, DIRECT], default-selected: DIRECT, hidden: true, icon: documentation, disable-udp: true}
 - {name: PublicAuto, type: url-test, proxies: [DIRECT, REJECT], url: 'http://probe.example/', interval: 300, timeout: 5000, max-failed-times: 2, lazy: false, tolerance: 15, expected-status: '200-299', empty-fallback: REJECT}
 - {name: PublicFallback, type: fallback, proxies: [DIRECT, REJECT], url: 'https://probe.example/', interval: 300, lazy: true, filter: DIRECT, exclude-filter: REJECT, exclude-type: ss}
rules: ['MATCH,PublicSelect']
`)
	plan := engine.Plan("group-supported", raw, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Groups) != 3 || plan.Groups[0].Members[0].DisplayName != "REJECT" || plan.Groups[0].Members[1].DisplayName != "DIRECT" {
		t.Fatalf("supported fields and source order must survive: %s/%s", plan.Category, plan.Code)
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result := engine.Validate("group-supported-validate", raw, prepared); result.Category != "pass" {
		t.Fatalf("supported group semantics: %s", result.Code)
	}
	candidate, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Discard(context.Background())
	if candidate.Proxies["PublicSelect"].Adapter().(interface{ Now() string }).Now() != "DIRECT" {
		t.Fatal("original default-selected must remain effective")
	}
	if engine.ResourceAcquireCount() != "0" {
		t.Fatal("group checks must not acquire resources")
	}
}
