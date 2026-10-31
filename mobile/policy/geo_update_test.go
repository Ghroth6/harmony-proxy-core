package policy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"google.golang.org/protobuf/proto"
)

func TestGeoAutoUpdateAdoptsNewMatcherAndJoinsAtStop(t *testing.T) {
	encode := func(domain string) []byte {
		data, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before, after := encode("before.example"), encode("after.example")
	encodeIP := func(address string) []byte {
		data, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "DOC", Cidr: []*router.CIDR{{Ip: netip.MustParseAddr(address).AsSlice(), Prefix: 24}}}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ipBefore, ipAfter := encodeIP("192.0.2.0"), encodeIP("198.51.100.0")
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/ip" {
			_, _ = w.Write(ipAfter)
		} else {
			_, _ = w.Write(after)
		}
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\ngeodata-mode: true\ngeodata-loader: standard\ngeo-auto-update: true\ngeo-update-interval: 1\ngeox-url: {geosite: '%s/site', geoip: '%s/ip'}\nrules: ['GEOSITE,DOC,REJECT', 'GEOIP,DOC,REJECT,no-resolve', 'MATCH,DIRECT']\n", server.URL, server.URL))
	plan := engine.Plan("geo-update", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 2 {
		t.Fatalf("plan %s/%s", plan.Category, plan.Code)
	}
	resources := []contract.Resource{}
	stale := time.Now().Add(-2 * time.Hour)
	for _, requirement := range plan.Requirements {
		data := before
		if requirement.Kind == "geoip" {
			data = ipBefore
		}
		r := savePublicResource(t, root, requirement, data)
		resources = append(resources, r)
		path := filepath.Join(root, filepath.FromSlash(r.RelativePath))
		if err = os.Chtimes(path, stale, stale); err != nil {
			t.Fatal(err)
		}
	}
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, resources, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("preparation opened geo updater")
	}
	ctx, generation := activatePublicPolicy(t, cfg, []string{}, &protected)
	if err = cfg.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		matchedSite, _ := cfg.Rules[0].Match(&C.Metadata{Host: "after.example"}, C.RuleMatchHelper{})
		matchedIP, _ := cfg.Rules[1].Match(&C.Metadata{DstIP: netip.MustParseAddr("198.51.100.1")}, C.RuleMatchHelper{})
		if matchedSite && matchedIP {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("downloaded GEO bytes never became the active matcher")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if match, _ := cfg.Rules[0].Match(&C.Metadata{Host: "before.example"}, C.RuleMatchHelper{}); match {
		t.Fatal("old GEO matcher remained active")
	}
	observed := engine.QueryResources("geo-observe", generation)
	if requests.Load() != 2 || protected.Load() == 0 || len(observed.Adopted) != 2 {
		t.Fatal("GEO publication and ledger disagree")
	}
	for _, adopted := range observed.Adopted {
		if adopted.ContentDigest != contract.Digest(after) && adopted.ContentDigest != contract.Digest(ipAfter) {
			t.Fatal("multi-GEO updater used another resource's bytes")
		}
	}
	cfg.CancelMobilePolicyServices()
	if err = cfg.WaitMobilePolicyServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = cfg.ActivateMobilePolicyResources(ctx); err == nil {
		t.Fatal("retired GEO timer restarted")
	}
}
