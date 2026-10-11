package policy_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"google.golang.org/protobuf/proto"
)

const geoPolicy = `ipv6: false
dns: {enable: false}
geodata-mode: true
geodata-loader: standard
rules:
 - GEOSITE,DOC,DIRECT
 - GEOIP,DOC,REJECT,no-resolve
 - MATCH,DIRECT
`

func TestOriginalPolicyUsesResourceScopedGeoMatchersWithoutGlobalCaches(t *testing.T) {
	var firstRules []C.Rule
	for _, fixture := range []struct{ domain, address string }{{"first.example", "192.0.2.1"}, {"second.example", "198.51.100.1"}} {
		root := t.TempDir()
		engine, err := policy.NewEngine(root)
		if err != nil {
			t.Fatal(err)
		}
		defer engine.Close()
		input := []byte(geoPolicy)
		plan := engine.Plan("geo-plan", input, nil)
		if plan.Category != "planned" || len(plan.Requirements) != 2 {
			t.Fatalf("geodata plan: %s/%s", plan.Category, plan.Code)
		}
		site, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: fixture.domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		ip, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "DOC", Cidr: []*router.CIDR{{Ip: netip.MustParseAddr(fixture.address).AsSlice(), Prefix: 24}}}}})
		if err != nil {
			t.Fatal(err)
		}
		resources := []contract.Resource{}
		for _, requirement := range plan.Requirements {
			payload := site
			if requirement.Kind == "geoip" {
				payload = ip
			}
			resources = append(resources, savePublicResource(t, root, requirement, payload))
		}
		prepared, err := contract.Seal(plan.InputDigest, resources, publicPlatform(), nil)
		if err != nil {
			t.Fatal(err)
		}
		baseline := engine.ResourceAcquireCount()
		candidate, err := engine.BuildCandidate(input, prepared)
		if err != nil {
			t.Fatalf("actual prepared geodata candidate: %s", err)
		}
		defer func() {
			if err := candidate.Discard(context.Background()); err != nil {
				t.Fatal(err)
			}
		}()
		if match, _ := candidate.Rules[0].Match(&C.Metadata{Host: "a." + fixture.domain}, C.RuleMatchHelper{}); !match {
			t.Fatal("source geosite bytes were not compiled")
		}
		if match, _ := candidate.Rules[1].Match(&C.Metadata{DstIP: netip.MustParseAddr(fixture.address)}, C.RuleMatchHelper{}); !match {
			t.Fatal("source geoip bytes were not compiled")
		}
		if firstRules == nil {
			firstRules = candidate.Rules
		} else {
			if match, _ := firstRules[0].Match(&C.Metadata{Host: "a.second.example"}, C.RuleMatchHelper{}); match {
				t.Fatal("new manifest replaced an older candidate's same-country matcher")
			}
			if match, _ := candidate.Rules[0].Match(&C.Metadata{Host: "a.first.example"}, C.RuleMatchHelper{}); match {
				t.Fatal("global country cache leaked into a new manifest")
			}
		}
		if engine.ResourceAcquireCount() != baseline {
			t.Fatal("geodata preparation made an acquisition")
		}
	}
}

func TestOriginalPolicyPlanRejectsMalformedBinaryInsteadOfMetadataOnlyReady(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['GEOSITE,DOC,DIRECT', 'MATCH,DIRECT']\n")
	plan := engine.Plan("bad-geodata-plan", input, nil)
	resource := savePublicResource(t, root, plan.Requirements[0], []byte{0xff, 0xff})
	actual := engine.Plan("bad-geodata-fixed", input, []contract.Resource{resource})
	if actual.Category == "planned" || actual.ResourcesComplete || actual.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" {
		t.Fatal("a hash alone must not mark invalid DAT as ready")
	}
}
