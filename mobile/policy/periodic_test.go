package policy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	"github.com/metacubex/mihomo/tunnel"
)

func TestOriginalProviderActivationWaitsFullIntervalSavesAndAdoptsActualBytes(t *testing.T) {
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Public-Fixture") != "documentation" {
			t.Error("original resource headers were lost")
		}
		if requests.Load() == 1 {
			fmt.Fprint(w, "payload:\n - DOMAIN-SUFFIX,updated.example\n")
		} else if requests.Load() == 2 {
			fmt.Fprint(w, "payload:\n - DOMAIN-SUFFIX\n")
		} else {
			fmt.Fprint(w, "payload:\n - GEOSITE,missing-documentation-group\n")
		}
	}))
	defer server.Close()
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline, err := strconv.ParseUint(engine.ResourceAcquireCount(), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	count := func(delta uint64) string { return strconv.FormatUint(baseline+delta, 10) }
	input := []byte(strings.ReplaceAll(strings.ReplaceAll(providerPolicy, "https://resources.example/rules.yaml", server.URL), "interval: 86400", "interval: 1, proxy: DIRECT, header: {X-Public-Fixture: [documentation]}"))
	plan := engine.Plan("periodic-plan", input, nil)
	resource := savePublicResource(t, root, plan.Requirements[0], []byte("payload:\n - DOMAIN-SUFFIX,documentation.example\n"))
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	published := false
	defer func() {
		if !published {
			_ = cfg.Discard(context.Background())
		}
	}()
	activation, ok := any(cfg).(interface{ ActivateMobilePolicyResources(context.Context) error })
	if !ok {
		_ = cfg.Discard(context.Background())
		t.Fatal("actual source resources require explicit owned activation")
	}
	generation := publicProtectedPolicy(t, func(g, request uint64, fd uintptr) int32 {
		protected.Add(1)
		return protection.Success
	})
	previous, _ := platformnetwork.Current()
	ng := previous.Generation + 1
	snapshot := []byte(fmt.Sprintf(`{"schemaVersion":1,"generation":%d,"networkId":1,"vpn":false,"online":true,"dns":[],"interfaces":[{"name":"public-loopback","mtu":1500,"up":true,"addresses":["127.0.0.1/8"],"routes":[{"destination":"0.0.0.0/0"}]}]}`, ng))
	if receipt := network.NewController(nil).Submit("periodic-network", snapshot); receipt.Category != "published" {
		t.Fatal("actual synthetic non-VPN snapshot rejected")
	}
	ctx, cancel := context.WithCancel(protection.WithGeneration(context.Background(), generation))
	defer cancel()
	tunnel.EnableForwardingLifecycle()
	if err = tunnel.PrepareForwarding(ctx, generation); err != nil {
		t.Fatal(err)
	}
	defer func() {
		tunnel.CancelForwarding()
		if err := tunnel.StopForwarding(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err = cfg.ActivateMobileNetwork(generation); err != nil {
		t.Fatal(err)
	}
	if err = executor.PublishMobilePolicy(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	published = true
	defer func() {
		if err := executor.RetireConfig(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err = tunnel.ActivateForwarding(generation); err != nil {
		t.Fatal(err)
	}
	if err = executor.ActivateMobilePolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if err = activation.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal(err)
	}
	if err = activation.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal("repeated activation must not create a second timer")
	}
	time.Sleep(200 * time.Millisecond)
	if requests.Load() != 0 || engine.ResourceAcquireCount() != count(0) {
		t.Fatal("prepared startup must not catch up old mtime or acquire immediately")
	}
	deadline := time.Now().Add(5 * time.Second)
	var observed policy.ResourcesReceipt
	for time.Now().Before(deadline) {
		observed = engine.QueryResources("periodic-query", generation)
		if len(observed.Adopted) == 1 && observed.Adopted[0].ContentDigest != resource.ContentDigest {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed.Category != "observed" || observed.CandidateDigest != prepared.CandidateDigest || observed.InitialManifestDigest != prepared.ResourceManifestDigest || len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest == resource.ContentDigest || observed.ResourceAcquireCount != count(1) {
		t.Fatalf("actual refresh must retain initial identity and publish a separate adopted revision: requests=%d protection=%d receipt=%+v", requests.Load(), protected.Load(), observed)
	}
	actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(observed.Adopted[0].RelativePath)))
	if err != nil || contract.Digest(actual) != observed.Adopted[0].ContentDigest {
		t.Fatal("saved event must identify actual immutable file bytes")
	}
	if matched, _ := cfg.Rules[0].Match(&C.Metadata{Host: "a.updated.example"}, C.RuleMatchHelper{}); !matched {
		t.Fatal("actual original provider strategy must adopt updated bytes")
	}
	if matched, _ := cfg.Rules[0].Match(&C.Metadata{Host: "a.documentation.example"}, C.RuleMatchHelper{}); matched {
		t.Fatal("updated strategy must replace the old matcher")
	}
	stages := map[string]bool{}
	for _, event := range observed.Events {
		if event.Generation != generation || event.NetworkGeneration != ng {
			t.Fatal("resource event requires the actual accepted run and network epoch")
		}
		stages[event.Stage] = true
	}
	for _, stage := range []string{"acquiring", "acquired", "saved", "adopted"} {
		if !stages[stage] {
			t.Fatal("resource ledger must observe actual ordered acquisition/save/adoption")
		}
	}
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		observed = engine.QueryResources("periodic-failure", generation)
		if len(observed.Events) > 0 && observed.Events[len(observed.Events)-1].Stage == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed.ResourceAcquireCount != count(2) || observed.Events[len(observed.Events)-1].Stage != "failed" || observed.Adopted[0].ContentDigest != contract.Digest(actual) || protected.Load() < 2 {
		t.Fatal("invalid acquired payload must count the attempt, retain old actual strategy and use protection")
	}
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		observed = engine.QueryResources("periodic-geo-closure", generation)
		if observed.ResourceAcquireCount == count(3) && len(observed.Events) > 0 && observed.Events[len(observed.Events)-1].Stage == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed.ResourceAcquireCount != count(3) || observed.Events[len(observed.Events)-1].Stage != "failed" || observed.Adopted[0].ContentDigest != contract.Digest(actual) {
		t.Fatal("a syntactically valid new geodata dependency must fail closed without implicit download or bad strategy adoption")
	}
	cancel()
	if err = executor.CancelConfigTasks(nil); err != nil {
		t.Fatal(err)
	}
}
