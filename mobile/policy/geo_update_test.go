package policy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(after) }))
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
	input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\ngeodata-loader: standard\ngeo-auto-update: true\ngeo-update-interval: 1\ngeox-url: {geosite: '%s'}\nrules: ['GEOSITE,DOC,REJECT', 'MATCH,DIRECT']\n", server.URL))
	plan := engine.Plan("geo-update", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 {
		t.Fatalf("plan %s/%s", plan.Category, plan.Code)
	}
	r := savePublicResource(t, root, plan.Requirements[0], before)
	path := filepath.Join(root, filepath.FromSlash(r.RelativePath))
	stale := time.Now().Add(-2 * time.Hour)
	if err = os.Chtimes(path, stale, stale); err != nil {
		t.Fatal(err)
	}
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{r}, platform, nil)
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
		if match, _ := cfg.Rules[0].Match(&C.Metadata{Host: "after.example"}, C.RuleMatchHelper{}); match {
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
	if requests.Load() != 1 || protected.Load() == 0 || len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest != contract.Digest(after) {
		t.Fatal("GEO publication and ledger disagree")
	}
	cfg.CancelMobilePolicyServices()
	if err = cfg.WaitMobilePolicyServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = cfg.ActivateMobilePolicyResources(ctx); err == nil {
		t.Fatal("retired GEO timer restarted")
	}
}
