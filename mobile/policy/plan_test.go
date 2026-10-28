package policy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestPolicyEngineCannotCloseWhileAcceptedCandidateOwnsResources(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	plan := engine.Plan("engine-owner-plan", input, nil)
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Discard(context.Background())
	if err = engine.Close(); err == nil {
		t.Fatal("closing the trusted root must retain an actual candidate owner rather than silently revoke its resource root")
	}
	if plan := engine.Plan("engine-owner-still-open", input, nil); plan.Category != "planned" {
		t.Fatal("busy Close must preserve the actual trusted-root owner")
	}
	if err = cfg.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	if plan := engine.Plan("engine-owner-retired", input, nil); plan.Category == "planned" || plan.ResourcesComplete {
		t.Fatal("a closed trusted root must not advertise a prepared policy")
	}
}

const originalPolicy = `proxies:
 - {name: PublicNode, type: ss, cipher: chacha20-ietf-poly1305, server: proxy.example, port: 8388, password: documentation-only, udp: true}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [PublicNode, DIRECT]}
 - {name: PublicAuto, type: url-test, proxies: [PublicNode], url: 'https://probe.example/', interval: 300}
rule-providers:
 PublicRules: {type: http, behavior: classical, url: 'https://resources.example/rules.yaml', path: './rules.yaml', interval: 86400}
rules:
 - RULE-SET,PublicRules,PublicSelect
 - GEOIP,CN,DIRECT
 - MATCH,PublicAuto
dns:
 enable: true
 nameserver: [192.0.2.53]
 nameserver-policy: {'geosite:cn': [192.0.2.54]}
profile: {store-selected: true}
`

func TestPolicyPlanPreservesOriginalGroupsAndDiscoversFixedResourcesWithoutNetwork(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	input := []byte(originalPolicy)
	plan := engine.Plan("policy-plan", input, nil)
	if plan.Category != "planned" || plan.Code != "" || plan.ResourcesComplete || len(plan.Groups) != 2 || !plan.GeneralIPv6 || plan.DNSIPv6 || !plan.DNSEnabled {
		t.Fatal("pure plan must preserve original defaults/groups and explicitly require fixed resources")
	}
	if plan.Groups[0].Type != "select" || len(plan.Groups[0].Members) != 2 || plan.Groups[0].Members[1].Kind != "builtin" || plan.Groups[1].Type != "url-test" {
		t.Fatal("plan must not reduce the original policy to selected-node MATCH")
	}
	kinds := make(map[string]bool)
	for _, requirement := range plan.Requirements {
		kinds[requirement.Kind] = true
		if !strings.HasPrefix(requirement.RefID, "sha256:") || !strings.HasPrefix(requirement.SourceDigest, "sha256:") {
			t.Fatal("resource requirements must have independent stable identities")
		}
		if requirement.Kind == "rule-provider" && (requirement.SourceURI != "https://resources.example/rules.yaml" || requirement.IntervalSeconds != 86400 || requirement.Format != "yaml") {
			t.Fatal("original resource source/interval/default format must be preserved privately")
		}
	}
	if !kinds["rule-provider"] || !kinds["mmdb"] || !kinds["geosite"] || engine.ResourceAcquireCount() != baseline {
		t.Fatal("plan must discover GEOIP and DNS GEOSITE dependencies without any resource acquisition")
	}
	digest := sha256.Sum256(input)
	if plan.InputDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("plan identity must bind actual original bytes")
	}
	changed := engine.Plan("policy-plan-changed", []byte(originalPolicy+"# source revision\n"), nil)
	if changed.Groups[0].GroupRef == plan.Groups[0].GroupRef || changed.Groups[0].Members[0].MemberRef == plan.Groups[0].Members[0].MemberRef {
		t.Fatal("group/member refs must be bound to raw revision, not display names")
	}
}

func TestPolicyResourceDiscoveryDoesNotTreatPrivateScalarsAsRules(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte(`ipv6: false
dns: {enable: false}
proxies:
 - {name: 'GEOSITE,documentation', type: ss, cipher: chacha20-ietf-poly1305, server: proxy.example, port: 8388, password: 'GEOIP,CN,IP-ASN,documentation', udp: true}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: ['GEOSITE,documentation']}
rules: ['MATCH,PublicSelect']
`)
	plan := engine.Plan("scoped-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Requirements) != 0 {
		t.Fatal("resource discovery must inspect actual rule/DNS fields, never credentials or display names")
	}
}

func TestPolicyPlanAcceptsTypedProfileTracingWithoutDroppingPolicy(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, value := range []string{"false", "true"} {
		plan := engine.Plan("profile-tracing", []byte("ipv6: false\ndns: {enable: false}\nprofile: {store-selected: true, store-fake-ip: false, tracing: "+value+"}\nrules: ['MATCH,DIRECT']\n"), nil)
		if plan.Category != "planned" || !plan.StoreSelected {
			t.Fatalf("typed client profile field must preserve the original policy: %s/%s", plan.Category, plan.Code)
		}
	}
	if plan := engine.Plan("profile-tracing-invalid", []byte("profile: {tracing: [documentation]}\nrules: ['MATCH,DIRECT']\n"), nil); plan.Category == "planned" {
		t.Fatal("tracing must retain its strict boolean type")
	}
}
