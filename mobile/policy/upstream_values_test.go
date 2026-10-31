package policy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"go.yaml.in/yaml/v3"
)

func TestRuleProviderPreparationUsesOfficialFieldDecoding(t *testing.T) {
	for _, test := range []struct {
		name, fields    string
		interval, limit int64
		invalid         bool
	}{
		{"numeric", "interval: 3600, size-limit: 1048576", 3600, 1048576, false},
		{"quoted", `interval: "3600", size-limit: "1048576", header: {X-Number: [123]}`, 3600, 1048576, false},
		{"large-interval", "interval: 2147483648", 2147483648, contract.MaxResourceBytes, false},
		{"nonpositive", "interval: -1, size-limit: -1", -1, contract.MaxResourceBytes, false},
		{"default", "x-note: ignored", 0, contract.MaxResourceBytes, false},
		{"invalid-interval", "interval: not-a-number", 0, 0, true},
		{"invalid-size", "size-limit: [1, 2]", 0, 0, true},
		{"invalid-header", "header: [1, 2]", 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nrule-providers:\n local: {type: http, behavior: domain, url: 'https://example.invalid/rules', %s}\nrules: ['RULE-SET,local,DIRECT', 'MATCH,DIRECT']\n", test.fields))
			raw, err := config.UnmarshalRawConfig(input)
			if err != nil {
				t.Fatal(err)
			}
			official, officialErr := RP.ParseRuleProvider("local", raw.RuleProvider["local"], rules.ParseRule, func(string) resource.BundleFile { return nil })
			if official != nil {
				defer func() {
					if err := official.(interface{ Close() error }).Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			if (officialErr != nil) != test.invalid {
				t.Fatalf("official parser: %v", officialErr)
			}
			root := t.TempDir()
			engine, err := policy.NewEngine(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := engine.Close(); err != nil {
					t.Error(err)
				}
			}()
			before := engine.ResourceAcquireCount()
			plan := engine.Plan("official-fields", input, nil)
			if test.invalid {
				if plan.Category == "planned" {
					t.Fatal("accepted invalid official provider fields")
				}
				return
			}
			if plan.Category != "planned" || len(plan.Requirements) != 1 {
				t.Fatalf("plan: %+v", plan)
			}
			requirement := plan.Requirements[0]
			if requirement.IntervalSeconds != test.interval || requirement.MaxBytes != test.limit {
				t.Fatalf("requirement: %+v", requirement)
			}
			if test.name == "quoted" && requirement.SourceHeadersJSON != `{"X-Number":["123"]}` {
				t.Fatal("header decoder semantics were lost")
			}
			fixed := savePublicResource(t, root, requirement, []byte("payload:\n - example.com\n"))
			platform := publicPlatform()
			platform.RuntimeOptions.ResourceDownloads = test.interval > 0
			prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{fixed}, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result := engine.Validate("official-fields-validate", input, prepared); result.Category != "pass" {
				t.Fatalf("validate: %+v", result)
			}
			candidate, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := candidate.Discard(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if matched, _ := candidate.Rules[0].Match(&C.Metadata{Host: "example.com"}, C.RuleMatchHelper{}); !matched {
				t.Fatalf("prepared provider lost actual rule matching: count=%d direct=%t rules=%#v", candidate.RuleProviders["local"].Count(), candidate.RuleProviders["local"].Match(&C.Metadata{Host: "example.com"}, C.RuleMatchHelper{}), candidate.Rules)
			}
			if engine.ResourceAcquireCount() != before {
				t.Fatal("preparation acquired resources")
			}
		})
	}
}

func TestPolicyNamesSurvivePlanBuildAndSelection(t *testing.T) {
	for _, name := range []string{strings.Repeat("界", 513), "first\nsecond\t\x00\x7f", "https://example.invalid/a-node"} {
		root := t.TempDir()
		engine, err := policy.NewEngine(root)
		if err != nil {
			t.Fatal(err)
		}
		input, err := yaml.Marshal(map[string]any{
			"ipv6": false, "dns": map[string]any{"enable": false},
			"proxies":      []any{map[string]any{"name": name, "type": "ss", "server": "example.invalid", "port": 8388, "cipher": "aes-128-gcm", "password": "documentation-only"}},
			"proxy-groups": []any{map[string]any{"name": "group:" + name, "type": "select", "proxies": []string{"DIRECT", name}}},
			"rules":        []string{"MATCH,DIRECT"},
		})
		if err != nil {
			t.Fatal(err)
		}
		plan := engine.Plan("original-names", input, nil)
		if plan.Category != "planned" || plan.Groups[0].DisplayName != "group:"+name || plan.Groups[0].Members[1].DisplayName != name {
			t.Fatalf("name lost: %s/%s", plan.Category, plan.Code)
		}
		prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}})
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := engine.BuildCandidate(input, prepared)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Proxies["group:"+name].Adapter().(interface{ Now() string }).Now() != name {
			t.Fatal("original-name selection changed")
		}
		if err := candidate.Discard(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
