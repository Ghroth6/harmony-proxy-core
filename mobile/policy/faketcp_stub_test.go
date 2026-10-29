//go:build !linux || no_fake_tcp

package policy_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

// This exercises real upstream construction, health checks and transport. The
// target build separately records its source selection because Windows already
// selects this stub without an explicit no_fake_tcp tag.
func TestFakeTCPStubKeepsMixedConfigAndFailsOnlyActualUse(t *testing.T) {
	const unsupported = "faketcp is not supported on this platform"
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Error("URL test did not issue HEAD")
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	input := []byte(fmt.Sprintf(`ipv6: false
dns: {enable: false}
proxies:
 - {name: DeferredFake, type: hysteria, server: 127.0.0.1, port: 443, protocol: faketcp, up: 10, down: 10}
proxy-providers:
 Nodes:
  type: inline
  payload:
   - {name: ProviderFake, type: hysteria, server: 127.0.0.1, port: 443, protocol: faketcp, up: 10, down: 10}
proxy-groups:
 - {name: Pick, type: select, proxies: [DIRECT, DeferredFake], use: [Nodes]}
 - {name: Automatic, type: url-test, proxies: [DeferredFake, DIRECT], use: [Nodes], url: '%s/automatic', interval: 1, lazy: true}
rules: ['MATCH,Pick']
`, server.URL))
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	plan := engine.Plan("mixed-faketcp-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete {
		t.Fatalf("unused fake-TCP rejected complete config: %s/%s", plan.Category, plan.Code)
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("mixed-faketcp-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("mixed config validation: %s/%s", receipt.Category, receipt.Code)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("preparation performed network activity")
	}
	results := make(chan adapter.URLTestEvent, 4)
	unsubscribe := adapter.SubscribeURLTests(func(event adapter.URLTestEvent) {
		if event.URL == server.URL+"/automatic" && (event.Name == "DeferredFake" || event.Name == "ProviderFake") {
			select {
			case results <- event:
			default:
			}
		}
	})
	t.Cleanup(unsubscribe)
	root, _ := activatePublicPolicy(t, cfg, []string{}, &protected, true)
	if err := executor.ActivateMobilePolicy(cfg); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for len(seen) < 2 {
		select {
		case event := <-results:
			if event.Succeeded || event.Err == nil || !strings.Contains(event.Err.Error(), unsupported) {
				t.Fatalf("automatic fake-TCP check did not preserve upstream error: %+v", event)
			}
			seen[event.Name] = true
		case <-time.After(3 * time.Second):
			t.Fatal("automatic health check did not publish both unsupported nodes")
		}
	}
	ctx, cancel := context.WithTimeout(root, 3*time.Second)
	defer cancel()
	for _, proxy := range []C.Proxy{cfg.Proxies["DeferredFake"], cfg.Providers["Nodes"].Proxies()[0]} {
		conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "destination.invalid", DstPort: 443})
		if conn != nil {
			_ = conn.Close()
			t.Fatal("fake-TCP stub returned a connection")
		}
		if err == nil || !strings.Contains(err.Error(), unsupported) {
			t.Fatalf("actual fake-TCP dial: %v", err)
		}
		if _, err := proxy.URLTest(ctx, server.URL+"/explicit", nil); err == nil || !strings.Contains(err.Error(), unsupported) {
			t.Fatalf("explicit fake-TCP URL test: %v", err)
		}
	}
	if _, err := cfg.Proxies["Pick"].URLTest(ctx, server.URL+"/usable", nil); err != nil {
		t.Fatalf("unused fake-TCP broke selected working node: %v", err)
	}
	if requests.Load() == 0 || protected.Load() == 0 {
		t.Fatal("selected usable node did not exchange real protected loopback traffic")
	}
}
