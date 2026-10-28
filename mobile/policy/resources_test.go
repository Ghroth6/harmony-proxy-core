package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
)

var publicPolicyGate protection.Gate
var publicPolicyGeneration atomic.Uint64
var publicPolicyHookOnce sync.Once
var publicPolicyHookStatus int32

func publicProtectedPolicy(t *testing.T, callback protection.Callback) uint64 {
	t.Helper()
	generation := publicPolicyGeneration.Add(1)
	publicPolicyHookOnce.Do(func() { publicPolicyHookStatus = publicPolicyGate.InstallDialerHook() })
	if publicPolicyHookStatus != protection.Success || publicPolicyGate.Register(generation, callback) != protection.Success {
		t.Fatal("actual process protection gate fixture")
	}
	t.Cleanup(func() {
		if publicPolicyGate.Unregister(generation) != protection.Success {
			t.Error("protection callback owner did not retire")
		}
	})
	return generation
}

func TestPolicyResourceManifestDoesNotRejectAnArbitraryTotalBudget(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	resources := []contract.Resource{}
	for _, name := range []string{"documentation-one", "documentation-two", "documentation-three"} {
		digest := contract.Digest([]byte(name))
		resources = append(resources, contract.Resource{RefID: digest, Kind: "mmdb", Format: "mmdb", SourceDigest: digest, ContentDigest: digest, ByteLength: 128 * 1024 * 1024, RelativePath: "immutable/" + digest[7:] + "/mmdb.mmdb"})
	}
	baseline := engine.ResourceAcquireCount()
	plan := engine.Plan("whole-resource-total-cap", []byte(noResourcePolicy), resources)
	if plan.Category != "invalid" || plan.ResourcesComplete || plan.Code != "POLICY_RESOURCE_READ_FAILED" || engine.ResourceAcquireCount() != baseline {
		t.Fatal("large resources must reach actual file validation without an arbitrary total quota")
	}
}

const providerPolicy = `ipv6: false
dns: {enable: false}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [DIRECT, REJECT]}
rule-providers:
 PublicRules: {type: http, behavior: classical, url: 'https://resources.example/rules.yaml', path: './rules.yaml', interval: 86400}
rules:
 - RULE-SET,PublicRules,PublicSelect
 - MATCH,DIRECT
`

func savePublicResource(t *testing.T, root string, requirement contract.Requirement, payload []byte) contract.Resource {
	t.Helper()
	digest := contract.Digest(payload)
	resource := contract.Resource{RefID: requirement.RefID, Kind: requirement.Kind, Format: requirement.Format, SourceDigest: requirement.SourceDigest, ContentDigest: digest, ByteLength: int64(len(payload)), RelativePath: "immutable/" + digest[7:] + "/" + requirement.Kind + "." + requirement.Format}
	path := filepath.Join(root, filepath.FromSlash(resource.RelativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	return resource
}

func TestFixedOriginalPolicyBuildsRealBoundProviderWithoutPreparationNetwork(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	input := []byte(providerPolicy)
	plan := engine.Plan("provider-plan", input, nil)
	resource := savePublicResource(t, root, plan.Requirements[0], []byte("payload:\n - DOMAIN-SUFFIX,documentation.example\n"))
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := engine.Validate("provider-validate", input, prepared)
	if receipt.Category != "pass" || receipt.CandidateDigest != prepared.CandidateDigest {
		t.Fatalf("verified provider must construct and retire original policy: %s/%s", receipt.Category, receipt.Code)
	}
	candidate, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatalf("actual fixed provider candidate: %s", err)
	}
	defer func() {
		if err := candidate.Discard(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()
	if len(candidate.Rules) != 2 || candidate.RuleProviders["PublicRules"].Count() != 1 {
		t.Fatal("original provider/rules were dropped")
	}
	matched, adapter := candidate.Rules[0].Match(&C.Metadata{Host: "a.documentation.example"}, C.RuleMatchHelper{})
	if !matched || adapter != "PublicSelect" {
		t.Fatal("candidate RULE-SET must bind its own actual provider, without published global state")
	}
	if matched, _ := candidate.Rules[0].Match(&C.Metadata{Host: "unmatched.example"}, C.RuleMatchHelper{}); matched {
		t.Fatal("fixed provider must retain its actual matching semantics")
	}
	if engine.ResourceAcquireCount() != baseline {
		t.Fatal("preparation must never download provider data")
	}
}

func TestFixedProviderRejectsForbiddenAndInlineRulesWithoutSkipping(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte(providerPolicy)
	plan := engine.Plan("forbidden-plan", input, nil)
	resource := savePublicResource(t, root, plan.Requirements[0], []byte("payload:\n - MATCH\n"))
	if receipt := engine.Plan("forbidden-match", input, []contract.Resource{resource}); receipt.Category == "planned" || receipt.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" {
		t.Fatal("provider MATCH cannot be silently skipped by the actual strategy")
	}
	inline := []byte("ipv6: false\ndns: {enable: false}\nrule-providers:\n PublicRules: {type: inline, behavior: classical, payload: ['DOMAIN-SUFFIX']}\nrules: ['RULE-SET,PublicRules,DIRECT', 'MATCH,DIRECT']\n")
	if receipt := engine.Plan("forbidden-inline", inline, nil); receipt.Category == "planned" || receipt.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" {
		t.Fatal("inline rules also need whole-payload strict validation")
	}
}

func TestFixedPolicyPlanVerifiesActualImmutableBytesAndStrictProviderPayload(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	input := []byte(providerPolicy)
	first := engine.Plan("fixed-first", input, nil)
	if first.Category != "planned" || first.ResourcesComplete || len(first.Requirements) != 1 {
		t.Fatal("fixed provider must be explicitly required before any acquisition")
	}
	resource := savePublicResource(t, root, first.Requirements[0], []byte("payload:\n - DOMAIN-SUFFIX,documentation.example\n - IP-CIDR,192.0.2.0/24,no-resolve\n"))
	ready := engine.Plan("fixed-ready", input, []contract.Resource{resource})
	if ready.Category != "planned" || !ready.ResourcesComplete || engine.ResourceAcquireCount() != baseline {
		t.Fatalf("real saved bytes must satisfy a fixed resource without HTTP: %s/%s", ready.Category, ready.Code)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(resource.RelativePath)), []byte("payload:\n - MATCH\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed := engine.Plan("fixed-mutated", input, []contract.Resource{resource})
	if changed.Category == "planned" || changed.ResourcesComplete || changed.Code != "POLICY_RESOURCE_DIGEST_INVALID" {
		t.Fatal("caller metadata cannot authorize changed actual file bytes")
	}
	invalid := savePublicResource(t, root, first.Requirements[0], []byte("payload:\n - DOMAIN-SUFFIX\n"))
	badPayload := engine.Plan("fixed-invalid-rule", input, []contract.Resource{invalid})
	if badPayload.Category == "planned" || badPayload.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" {
		t.Fatal("malformed provider rules must reject the complete resource, never log and skip")
	}
	escape := resource
	escape.RelativePath = "../outside.yaml"
	if receipt := engine.Plan("fixed-escape", input, []contract.Resource{escape}); receipt.Category == "planned" || receipt.Code != "POLICY_RESOURCE_PATH_INVALID" {
		t.Fatal("only exact digest-addressed trusted-root paths are permitted")
	}
	if receipt := engine.Plan("fixed-duplicate", input, []contract.Resource{resource, resource}); receipt.Category == "planned" || receipt.Code != "POLICY_RESOURCE_IDENTITY_INVALID" {
		t.Fatal("duplicate resource refs must be rejected before loading")
	}
}
