package policy_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func TestProxyProvidersKeepCachePayloadAndPartialInitialization(t *testing.T) {
	if os.Getenv("MIHOMO_PROVIDER_LIFECYCLE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProxyProvidersKeepCachePayloadAndPartialInitialization$")
		cmd.Env = append(os.Environ(), "MIHOMO_PROVIDER_LIFECYCLE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated process cache lifetime: %s: %v", output, err)
		}
		return
	}
	root := t.TempDir()
	t.Cleanup(func() {
		if db := cachefile.Cache().DB; db != nil {
			_ = db.Close()
		}
	})
	old := C.Path.HomeDir()
	C.SetHomeDir(root)
	t.Cleanup(func() { C.SetHomeDir(old) })
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/missing" {
			http.Error(w, "unavailable", 503)
			return
		}
		fmt.Fprintln(w, "proxies: [{name: Fresh, type: direct}]")
	}))
	t.Cleanup(server.Close)
	if err := os.WriteFile(filepath.Join(root, "cached.yaml"), []byte("proxies: [{name: Cached, type: direct}]"), 0600); err != nil {
		t.Fatal(err)
	}
	input := []byte(fmt.Sprintf(`ipv6: false
dns: {enable: false}
proxy-providers:
 Cached: {type: http, url: '%s/cached', path: cached.yaml, interval: 0}
 Remote: {type: http, url: '%s/remote', interval: 0}
 Broken: {type: http, url: '%s/missing', interval: 0, payload: [{name: Fallback, type: direct}]}
 Empty: {type: file, path: absent.yaml}
proxy-groups:
 - {name: Pick, type: select, use: [Cached, Remote, Broken]}
 - {name: EmptyGroup, type: select, use: [Empty]}
rules: ['MATCH,Pick']
`, server.URL, server.URL, server.URL))
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	plan := engine.Plan("provider-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || !plan.RuntimeDownloads {
		t.Fatalf("plan: %s/%s", plan.Category, plan.Code)
	}
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("preparation acquired a provider")
	}
	activatePublicPolicy(t, cfg, []string{}, &protected)
	if requests.Load() != 2 || protected.Load() == 0 {
		t.Fatalf("cache priority or protected acquisition lost: requests=%d protected=%d", requests.Load(), protected.Load())
	}
	for name, node := range map[string]string{"Cached": "Cached", "Remote": "Fresh", "Broken": "Fallback"} {
		ps := cfg.Providers[name].Proxies()
		if len(ps) != 1 || ps[0].Name() != node {
			t.Fatalf("%s lost upstream result: %v", name, ps)
		}
	}
	if cfg.Proxies["EmptyGroup"].Adapter().(interface{ Now() string }).Now() != "COMPATIBLE" {
		t.Fatal("empty group must retain upstream fallback")
	}
	if err := cfg.Providers["Remote"].Update(); err != nil {
		t.Fatal(err)
	}
	cfg.CancelMobilePolicyServices()
	if err := cfg.WaitMobilePolicyServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	if err := cfg.Providers["Remote"].Update(); err == nil || requests.Load() != before {
		t.Fatal("retired provider acquired again")
	}
}

func TestOriginalMRSUsesUpstreamBinaryDecoder(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nrule-providers:\n Docs: {type: file, path: docs.mrs, format: mrs, behavior: domain}\nrules: ['RULE-SET,Docs,REJECT', 'MATCH,DIRECT']\n")
	plan := engine.Plan("mrs-plan", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 {
		t.Fatalf("plan: %s/%s", plan.Category, plan.Code)
	}
	var encoded bytes.Buffer
	if err := RP.ConvertToMrs([]byte("payload:\n - '+.documentation.example'\n"), P.Domain, P.YamlRule, &encoded); err != nil {
		t.Fatal(err)
	}
	r := savePublicResource(t, root, plan.Requirements[0], encoded.Bytes())
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{r}, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Discard(context.Background())
	if ok, _ := cfg.Rules[0].Match(&C.Metadata{Host: "a.documentation.example"}, C.RuleMatchHelper{}); !ok {
		t.Fatal("binary rules not installed")
	}
}

func TestPolicyAcceptsOriginalInputAndGroupsAboveFormerQuotas(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var input strings.Builder
	input.WriteString("ipv6: false\ndns: {enable: false}\nproxy-groups:\n")
	for i := 0; i < 513; i++ {
		fmt.Fprintf(&input, " - {name: G%d, type: select, proxies: [DIRECT]}\n", i)
	}
	input.WriteString("rules: ['MATCH,DIRECT']\n#")
	input.WriteString(strings.Repeat("x", 1024*1024))
	plan := engine.Plan("large-input", []byte(input.String()), nil)
	if plan.Category != "planned" || len(plan.Groups) != 513 {
		t.Fatalf("retained artificial admission quota: %s/%s", plan.Category, plan.Code)
	}
}
