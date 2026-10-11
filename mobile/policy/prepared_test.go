package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

const noResourcePolicy = `ipv6: false
dns: {enable: false}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [REJECT, DIRECT]}
rules:
 - DOMAIN,documentation.example,REJECT
 - MATCH,PublicSelect
profile: {store-selected: true}
`

func publicPlatform() contract.Platform {
	return contract.Platform{RuntimeOptions: contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true}, PlatformPolicy: contract.PlatformPolicy{Revision: "public-policy-v1", AddressFamily: "ipv4", ApplicationIDs: []string{}}, TunPolicy: contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}}
}

func TestOriginalPolicyCandidateIdentityDoesNotAliasCallerOrReturnedSlices(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte(noResourcePolicy)
	platform := publicPlatform()
	platform.PlatformPolicy.ApplicationIDs = []string{"org.example.public"}
	prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Discard(context.Background())
	prepared.Platform.PlatformPolicy.ApplicationIDs[0] = "org.example.mutated"
	first, _ := candidate.MobilePolicyContext()
	if first.Platform.PlatformPolicy.ApplicationIDs[0] != "org.example.public" {
		t.Fatal("accepted identity aliases mutable caller input")
	}
	first.Platform.PlatformPolicy.ApplicationIDs[0] = "org.example.returned"
	second, _ := candidate.MobilePolicyContext()
	if second.Platform.PlatformPolicy.ApplicationIDs[0] != "org.example.public" {
		t.Fatal("accepted identity aliases a returned copy")
	}
}

func TestOriginalPolicyBuildPreservesRulesAndOpaqueSelectionWithoutPreparationNetwork(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	input := []byte(noResourcePolicy)
	plan := engine.Plan("original-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Requirements) != 0 {
		t.Fatal("resource-free original policy must plan without fetching")
	}
	prefs := []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), prefs)
	if err != nil {
		t.Fatal(err)
	}
	validated := engine.Validate("original-validate", input, prepared)
	if validated.Category != "pass" || validated.CandidateDigest != prepared.CandidateDigest || validated.ResourceManifestDigest != prepared.ResourceManifestDigest || engine.ResourceAcquireCount() != baseline {
		t.Fatalf("actual construction and cleanup must validate the independent source identities: %s/%s", validated.Category, validated.Code)
	}
	first, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatalf("original candidate: %s", err)
	}
	defer first.Discard(context.Background())
	second, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal("independent second construction")
	}
	defer second.Discard(context.Background())
	if len(first.Rules) != 2 || first.Rules[0].Adapter() != "REJECT" || first.Rules[1].Adapter() != "PublicSelect" || first.Proxies["DIRECT"] == second.Proxies["DIRECT"] || first.General.IPv6 || first.General.FindProcessMode == process.FindProcessOff {
		t.Fatal("original rules/default process mode and fresh adapters must survive candidate construction")
	}
	selection, ok := first.Proxies["PublicSelect"].Adapter().(interface{ Now() string })
	if !ok || selection.Now() != "DIRECT" {
		t.Fatal("only the raw-bound declared select preference must be applied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = first.Proxies["DIRECT"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "never-contact.example", DstPort: 80})
	if err == nil || err.Error() != "preparation network is forbidden" {
		t.Fatal("original DIRECT must also be fenced before activation")
	}
	mutated := prepared
	mutated.CandidateDigest = contract.Digest([]byte("untrusted"))
	rejected := engine.Validate("original-mutation", input, mutated)
	if rejected.Category == "pass" || rejected.CandidateDigest != "" || rejected.ResourceManifestDigest != "" || rejected.PlatformPolicyDigest != "" || rejected.GroupPreferencesDigest != "" {
		t.Fatal("negative receipts must never echo caller identity claims")
	}
}
