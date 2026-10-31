package policy_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"google.golang.org/protobuf/proto"
)

func TestPublishedMobileGeneralUsesOfficialOutboundSettings(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	input := []byte("ipv6: false\ndns: {enable: false}\nlog-level: debug\nunified-delay: true\ntcp-concurrent: true\nkeep-alive-idle: 37\nkeep-alive-interval: 19\ndisable-keep-alive: true\nglobal-ua: PublicCompatibility/1\netag-support: false\nrules: ['MATCH,DIRECT']\n")
	plan := engine.Plan("general-plan", input, nil)
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var protected atomic.Int32
	activatePublicPolicy(t, cfg, []string{}, &protected)
	actual := executor.GetGeneral()
	if actual.LogLevel != log.DEBUG || !actual.UnifiedDelay || !actual.TCPConcurrent || actual.KeepAliveIdle != 37 || actual.KeepAliveInterval != 19 || !actual.DisableKeepAlive || actual.GlobalUA != "PublicCompatibility/1" || actual.ETagSupport {
		t.Fatalf("parsed outbound settings did not reach runtime: %+v", actual)
	}
}

func TestGeoPreparationKeepsOfficialAttributesAndUnusedGroups(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\ngeodata-loader: standard\nrule-providers:\n Local: {type: inline, behavior: classical, payload: ['GEOSITE,DOC@one@two,ignored-param']}\nrules: ['RULE-SET,Local,DIRECT', 'MATCH,REJECT']\n")
	plan := engine.Plan("geo-compatible", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	data, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{
		{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "attributes.example", Attribute: []*router.Domain_Attribute{{Key: "one"}, {Key: "two"}}}}},
		{CountryCode: "UNUSED", Domain: []*router.Domain{{Type: router.Domain_Regex, Value: "["}}},
		{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "duplicate.example"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixed := savePublicResource(t, root, plan.Requirements[0], data)
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{fixed}, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("geo-compatible-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("validate: %+v", receipt)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Discard(context.Background())
	if match, _ := cfg.Rules[0].Match(&C.Metadata{Host: "attributes.example"}, C.RuleMatchHelper{}); !match {
		t.Fatal("multiple official attributes or ignored parameters were filtered")
	}
	if match, _ := cfg.Rules[0].Match(&C.Metadata{Host: "duplicate.example"}, C.RuleMatchHelper{}); match {
		t.Fatal("official first matching group behavior changed")
	}
}

func TestBuiltInLANGeoRulesDoNotRequireADatabase(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['AND,((GEOIP,LAN),(NETWORK,TCP)),DIRECT', 'SRC-GEOIP,LAN,DIRECT', 'MATCH,REJECT']\n")
	plan := engine.Plan("lan-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || len(plan.Requirements) != 0 {
		t.Fatalf("built-in LAN rule required a GEO file: %+v", plan)
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Discard(context.Background())
	if match, _ := cfg.Rules[0].Match(&C.Metadata{DstIP: netip.MustParseAddr("192.168.1.2"), NetWork: C.TCP}, C.RuleMatchHelper{}); !match {
		t.Fatal("built-in LAN matcher lost")
	}
}
