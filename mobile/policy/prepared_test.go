package policy_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestOriginalPolicyValidationRetainsVerifiedProcessAdaptationAndClosesOwners(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['PROCESS-NAME,org.example.public,DIRECT', 'MATCH,DIRECT']\n")
	prepared, err := contract.Seal(contract.Digest(input), nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := engine.Validate("verified-process-adaptation", input, prepared)
	if receipt.Category != "pass" || !slices.Contains(receipt.Uncovered, "ohos-process-owner-lookup") || !slices.Contains(receipt.Covered, "candidate-resources-closed") {
		t.Fatalf("validated plan adaptation was lost: %s/%s", receipt.Category, receipt.Code)
	}
	if err := engine.Close(); err != nil {
		t.Fatal("validation retained an actual candidate or resource owner")
	}
}

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
	return contract.Platform{RuntimeOptions: contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true}, PlatformPolicy: contract.PlatformPolicy{Revision: "public-policy-v1", AddressFamily: "ipv4", ApplicationIDs: []string{"org.example.public"}}, TunPolicy: contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}}
}

func TestOriginalPolicyRejectsEmptyLegacyApplicationScope(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	platform := publicPlatform()
	platform.PlatformPolicy.ApplicationIDs = []string{}
	prepared, err := contract.Seal(contract.Digest([]byte(noResourcePolicy)), nil, platform, nil)
	if err != nil {
		return
	}
	receipt := engine.Validate("empty-legacy-scope", []byte(noResourcePolicy), prepared)
	if receipt.Category == "pass" || receipt.CandidateDigest != "" {
		t.Fatal("an empty legacy application list must never authorize an original-policy candidate")
	}
}

func TestOriginalPolicyAcceptsExplicitAllApplicationsWithIndependentIdentity(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	platform := publicPlatform()
	if err = json.Unmarshal([]byte(`{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"all","applicationIds":[]}`), &platform.PlatformPolicy); err != nil {
		t.Fatal(err)
	}
	input := []byte(noResourcePolicy)
	prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := engine.ValidateJSON("all-application-policy", input, encoded)
	if err != nil || receipt.Category != "pass" || receipt.CandidateDigest != prepared.CandidateDigest {
		t.Fatalf("explicit all-application policy must construct and close a real candidate: %v %s/%s", err, receipt.Category, receipt.Code)
	}
}

func TestOriginalPolicyApplicationScopeCannotBroadenAmbiguousOrInvalidValues(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte(noResourcePolicy)
	for name, text := range map[string]string{
		"legacy":          `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationIds":["org.example.public"]}`,
		"include":         `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"include","applicationIds":["org.example.public"]}`,
		"all":             `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"all","applicationIds":[]}`,
		"empty legacy":    `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationIds":[]}`,
		"empty include":   `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"include","applicationIds":[]}`,
		"conflicting all": `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"all","applicationIds":["org.example.public"]}`,
		"unknown":         `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"exclude","applicationIds":["org.example.public"]}`,
		"empty scope":     `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationScope":"","applicationIds":["org.example.public"]}`,
		"invalid id":      `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationIds":["bad"]}`,
		"duplicate":       `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationIds":["org.example.public","org.example.public"]}`,
		"over capacity":   `{"revision":"public-policy-v1","addressFamily":"ipv4","applicationIds":[` + strings.TrimSuffix(strings.Repeat(`"org.example.public",`, 17), ",") + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			platform := publicPlatform()
			if err := json.Unmarshal([]byte(text), &platform.PlatformPolicy); err != nil {
				t.Fatal(err)
			}
			prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(prepared)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := engine.ValidateJSON("scope-acceptance", input, encoded)
			accepted := name == "legacy" || name == "include" || name == "all"
			if err != nil || (receipt.Category == "pass") != accepted {
				t.Fatalf("scope acceptance %s: %v %s/%s", name, err, receipt.Category, receipt.Code)
			}
			if !accepted && (receipt.CandidateDigest != "" || receipt.PlatformPolicyDigest != "") {
				t.Fatal("invalid scope echoed caller identities")
			}
			if name == "all" {
				for _, invalid := range []string{
					strings.Replace(string(encoded), `"applicationScope":"all"`, `"applicationScope":null`, 1),
					strings.Replace(string(encoded), `"applicationIds":[],`, ``, 1),
					strings.Replace(string(encoded), `"applicationIds":[]`, `"applicationIds":null`, 1),
				} {
					if _, err := engine.ValidateJSON("scope-wire-rejection", input, []byte(invalid)); err == nil {
						t.Fatal("missing/null scope authority accepted by strict wire")
					}
				}
			}
		})
	}
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
