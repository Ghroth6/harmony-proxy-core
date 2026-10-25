package policy_test

import (
	"bytes"
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestOriginalPolicyExpandedGroupsKeepUpstreamOrderAndSelectionIdentity(t *testing.T) {
	input := []byte(`ipv6: false
dns: {enable: false}
proxies:
 - {name: Zulu, type: direct}
 - {name: Alpha, type: direct}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [REJECT], include-all-proxies: true}
 - {name: PublicBalance, type: load-balance, proxies: [DIRECT], include-all: true, strategy: consistent-hashing, hash-key: in-user}
rules:
 - DOMAIN,one.invalid,PublicSelect
 - MATCH,PublicBalance
`)
	original := bytes.Clone(input)
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	plan := engine.Plan("upstream-groups-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Groups) != 2 {
		t.Fatalf("real implemented groups must plan: %s/%s", plan.Category, plan.Code)
	}
	for index, expected := range [][]string{{"REJECT", "Alpha", "Zulu"}, {"DIRECT", "Alpha", "Zulu"}} {
		group := plan.Groups[index]
		if group.Position != index+1 || len(group.Members) != len(expected) {
			t.Fatal("effective original group position or members changed")
		}
		for member, name := range expected {
			if group.Members[member].DisplayName != name {
				t.Fatal("upstream expansion order changed")
			}
		}
	}
	preferences := []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[2].MemberRef}}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), preferences)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("upstream-groups-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("effective selector preference must validate: %s", receipt.Code)
	}
	candidate, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Discard(context.Background())
	if candidate.Proxies["PublicSelect"].Adapter().(interface{ Now() string }).Now() != "Zulu" {
		t.Fatal("effective member identity did not select Zulu")
	}
	if candidate.Proxies["PublicBalance"].Type() != C.LoadBalance || len(candidate.Rules) != 2 || candidate.Rules[0].Adapter() != "PublicSelect" || candidate.Rules[1].Adapter() != "PublicBalance" {
		t.Fatal("real upstream group or original rule order changed")
	}
	if !bytes.Equal(input, original) || engine.ResourceAcquireCount() != baseline {
		t.Fatal("preparation changed original bytes or acquired resources")
	}
}
