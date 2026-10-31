package policy_test

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

// Generated from testdata/bundle-src/bundled.txt with the ordinary 7z writer.
//
//go:embed testdata/rules-bundle.7z
var publicRuleBundle []byte

func TestRuleResourcesUseOfficialCacheBundleFallbackFileWatchAndETag(t *testing.T) {
	if os.Getenv("MIHOMO_RULE_RESOURCE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRuleResourcesUseOfficialCacheBundleFallbackFileWatchAndETag$")
		cmd.Env = append(os.Environ(), "MIHOMO_RULE_RESOURCE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated cache lifetime: %s: %v", output, err)
		}
		return
	}
	root := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(root)
	t.Cleanup(func() {
		if db := cachefile.Cache().DB; db != nil {
			_ = db.Close()
		}
		C.SetHomeDir(oldHome)
	})
	for name, data := range map[string][]byte{
		"file.txt":     []byte("DOMAIN-SUFFIX,file-before.example\n"),
		"cache.txt":    []byte("DOMAIN-SUFFIX,cached.example\n"),
		"bundlemrs.7z": publicRuleBundle,
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var requests, protected, conditional atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/missing":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/empty":
			w.WriteHeader(http.StatusOK)
		case "/remote":
			if r.Header.Get("If-None-Match") == `"public-v1"` {
				conditional.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"public-v1"`)
			fmt.Fprintln(w, "DOMAIN-SUFFIX,remote.example")
		default:
			t.Errorf("cache/bundle should avoid HTTP: %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	}))
	t.Cleanup(server.Close)
	input := []byte(fmt.Sprintf(`ipv6: false
dns: {enable: false}
etag-support: true
rule-providers:
 File: {type: file, path: file.txt, behavior: classical, format: text}
 Cache: {type: http, path: cache.txt, url: '%s/cache', interval: 0, behavior: classical, format: text}
 Bundle: {type: http, path: bundle.txt, path-in-bundle: bundled.txt, url: '%s/bundle', interval: 0, behavior: classical, format: text}
 Remote: {type: http, path: remote.txt, url: '%s/remote', interval: 0, behavior: classical, format: text}
 Empty: {type: http, path: empty.txt, url: '%s/empty', interval: 0, behavior: classical, format: text}
 Fallback: {type: http, path: missing.txt, url: '%s/missing', interval: 0, behavior: classical, format: text, payload: ['DOMAIN-SUFFIX,fallback.example']}
 MissingFile: {type: file, path: missing-file.txt, behavior: classical, format: text, payload: ['DOMAIN-SUFFIX,missing-file.example']}
rules: ['RULE-SET,File,DIRECT', 'RULE-SET,Cache,DIRECT', 'RULE-SET,Bundle,DIRECT', 'RULE-SET,Remote,DIRECT', 'RULE-SET,Empty,DIRECT', 'RULE-SET,Fallback,DIRECT', 'RULE-SET,MissingFile,DIRECT', 'MATCH,DIRECT']
`, server.URL, server.URL, server.URL, server.URL, server.URL))
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	baseline := engine.ResourceAcquireCount()
	plan := engine.Plan("compatible-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete || !plan.RuntimeDownloads || len(plan.Requirements) != 7 {
		t.Fatalf("plan: %+v", plan)
	}
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("compatible-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("validate: %+v", receipt)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("preparation acquired resources")
	}
	ctx, generation := activatePublicPolicy(t, cfg, []string{}, &protected)
	if err := cfg.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 3 || protected.Load() == 0 {
		t.Fatalf("requests=%d protected=%d", requests.Load(), protected.Load())
	}
	for name, host := range map[string]string{"File": "file-before.example", "Cache": "cached.example", "Bundle": "bundled.example", "Remote": "remote.example", "Fallback": "fallback.example", "MissingFile": "missing-file.example"} {
		if !cfg.RuleProviders[name].Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
			t.Fatalf("%s lost actual strategy", name)
		}
	}
	if cfg.RuleProviders["Empty"].Count() != 0 {
		t.Fatal("empty text must yield an empty strategy")
	}
	observed := engine.QueryResources("compatible-observe", generation)
	if len(observed.Adopted) != 5 {
		t.Fatalf("cache, bundle, file, HTTP and empty need adopted records: %+v", observed)
	}
	adoptedCount := func(receipt policy.ResourcesReceipt) int {
		n := 0
		for _, event := range receipt.Events {
			if event.Stage == "adopted" {
				n++
			}
		}
		return n
	}
	if adoptedCount(observed) != 5 {
		t.Fatalf("initial cache/bundle adoption missing: %+v", observed.Events)
	}
	for _, version := range observed.Adopted {
		actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(version.RelativePath)))
		if err != nil || contract.Digest(actual) != version.ContentDigest {
			t.Fatal("ledger does not name immutable actual bytes")
		}
	}
	if err := cfg.RuleProviders["Remote"].Update(); err != nil {
		t.Fatal(err)
	}
	if conditional.Load() != 1 || adoptedCount(engine.QueryResources("compatible-304", generation)) != 5 {
		t.Fatal("304 must preserve strategy and immutable adoption")
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("DOMAIN-SUFFIX,file-after.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !cfg.RuleProviders["File"].Match(&C.Metadata{Host: "file-after.example"}, C.RuleMatchHelper{}) {
		if time.Now().After(deadline) {
			t.Fatal("official file watch did not publish changed file")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cfg.RuleProviders["File"].Match(&C.Metadata{Host: "file-before.example"}, C.RuleMatchHelper{}) {
		t.Fatal("old file strategy survived")
	}
	if adoptedCount(engine.QueryResources("compatible-watch", generation)) != 6 {
		t.Fatal("file watch update did not get an immutable adopted revision")
	}
	cfg.CancelMobilePolicyServices()
	if err := cfg.WaitMobilePolicyServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cfg.RuleProviders["Remote"].Update(); err == nil || requests.Load() != 4 {
		t.Fatal("retired provider made a new request")
	}
}

func TestEmptyFixedTextAndStalePreparedRuleUseOfficialBehavior(t *testing.T) {
	for _, empty := range []bool{true, false} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			var requests, protected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				fmt.Fprintln(w, "DOMAIN-SUFFIX,fresh.example")
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
			input := []byte(strings.ReplaceAll(strings.ReplaceAll(providerPolicy, "https://resources.example/rules.yaml", server.URL), "interval: 86400", "interval: 3600, format: text"))
			plan := engine.Plan("stale-plan", input, nil)
			payload := []byte("DOMAIN-SUFFIX,old.example\n")
			if empty {
				payload = []byte{}
			}
			fixed := savePublicResource(t, root, plan.Requirements[0], payload)
			stale := time.Now().Add(-2 * time.Hour)
			if err := os.Chtimes(filepath.Join(root, filepath.FromSlash(fixed.RelativePath)), stale, stale); err != nil {
				t.Fatal(err)
			}
			platform := publicPlatform()
			platform.RuntimeOptions.ResourceDownloads = true
			prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{fixed}, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			if receipt := engine.Validate("stale-validate", input, prepared); receipt.Category != "pass" {
				t.Fatalf("validate %+v", receipt)
			}
			cfg, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if empty && cfg.RuleProviders["PublicRules"].Count() != 0 {
				t.Fatal("empty fixed text rejected")
			}
			ctx, _ := activatePublicPolicy(t, cfg, []string{}, &protected)
			if err := cfg.ActivateMobilePolicyResources(ctx); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for !cfg.RuleProviders["PublicRules"].Match(&C.Metadata{Host: "fresh.example"}, C.RuleMatchHelper{}) {
				if time.Now().After(deadline) {
					t.Fatal("stale prepared resource waited a full interval")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if requests.Load() == 0 || protected.Load() == 0 {
				t.Fatal("stale initial refresh did not use the owned network")
			}
		})
	}
}
