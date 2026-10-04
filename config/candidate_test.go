package config_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor" // supplies temporaryUpdateGeneral
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/tunnel"
)

func anyTLSCandidate(name string) map[string]any {
	return map[string]any{"name": name, "type": "anytls", "server": "127.0.0.1", "port": 443, "password": "candidate-test"}
}

func candidateRoutines() int {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "github.com/metacubex/mihomo/transport/anytls/util.StartRoutine.func1(")
}

func TestCandidateFailureClosesResourcesFromEveryParsingStage(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.RawConfig)
		wantError string
	}{
		{"partial-proxy", func(c *config.RawConfig) {
			c.Proxy = append(c.Proxy, map[string]any{"name": "invalid", "type": "unknown"})
		}, "proxy 1"},
		{"duplicate-proxy", func(c *config.RawConfig) { c.Proxy = append(c.Proxy, anyTLSCandidate("owned")) }, "duplicate name"},
		{"missing-group-name", func(c *config.RawConfig) { c.ProxyGroup = []map[string]any{{"type": "select"}} }, "missing name"},
		{"invalid-group-regex", func(c *config.RawConfig) {
			c.ProxyGroup = []map[string]any{{"name": "invalid", "type": "select", "include-all-proxies": true, "filter": "["}}
		}, "invalid filter regex"},
		{"group-after-compatible-provider", func(c *config.RawConfig) {
			c.ProxyGroup = []map[string]any{{"name": "invalid-group", "type": "unknown", "proxies": []string{"owned"}}}
		}, "unsupported type"},
		{"duplicate-group", func(c *config.RawConfig) {
			c.ProxyGroup = []map[string]any{{"name": "owned", "type": "select", "proxies": []string{"DIRECT"}}}
		}, "duplicate name"},
		{"provider", func(c *config.RawConfig) { c.ProxyProvider = map[string]map[string]any{"invalid": {"type": "unknown"}} }, "proxy provider invalid"},
		{"partial-inline-provider", func(c *config.RawConfig) {
			c.ProxyProvider = map[string]map[string]any{"partial": {"type": "inline", "payload": []map[string]any{anyTLSCandidate("owned-by-provider"), {"name": "invalid", "type": "unknown"}}}}
		}, "parse proxy provider partial"},
		{"dialer-reference", func(c *config.RawConfig) { c.Proxy[0]["dialer-proxy"] = "missing" }, "not found"},
		{"listener", func(c *config.RawConfig) {
			c.Listeners = []map[string]any{{"name": "valid", "type": "http", "port": 19089}, {"name": "invalid", "type": "unknown"}}
		}, "listener 1"},
		{"rule-provider", func(c *config.RawConfig) {
			c.RuleProvider = map[string]map[string]any{"invalid": {"type": "unknown", "behavior": "domain"}}
		}, "vehicle type"},
		{"subrules", func(c *config.RawConfig) { c.SubRules = map[string][]string{"": {"MATCH,DIRECT"}} }, "sub-rule name is empty"},
		{"rules", func(c *config.RawConfig) { c.Rule = []string{"MATCH,missing"} }, "proxy [missing] not found"},
		{"hosts", func(c *config.RawConfig) { c.Hosts = map[string]any{"example.test": []string{"127.0.0.1", "invalid!"}} }, "not a valid value"},
		{"dns", func(c *config.RawConfig) { c.DNS.Enable = true; c.DNS.NameServer = nil }, "NameServer cannot be empty"},
		{"after-tun", func(c *config.RawConfig) { c.Tun.Enable = true; c.Tunnels = []LC.Tunnel{{Proxy: "missing"}} }, "tunnel proxy missing"},
		{"sniffer", func(c *config.RawConfig) { c.Sniffer.Sniffing = []string{"unknown"} }, "not find the sniffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := candidateRoutines()
			raw := config.DefaultRawConfig()
			raw.Proxy = []map[string]any{anyTLSCandidate("owned")}
			raw.ProxyProvider = map[string]map[string]any{"inline": {"type": "inline", "payload": []map[string]any{anyTLSCandidate("subscribed")}}}
			tt.mutate(raw)
			cfg, err := config.ParseRawConfig(raw)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("ParseRawConfig = %v, %v; want %q", cfg, err, tt.wantError)
			}
			if cfg != nil {
				t.Fatal("failed candidate was returned as usable")
			}
			if err := config.WaitCleanup(context.Background(), err); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			// Close promises to join the real idle routine; no GC/finalizer or
			// eventual 30-second timer tick is allowed to repair this assertion.
			if after := candidateRoutines(); after != before {
				t.Fatalf("AnyTLS idle routines: before %d, after failure %d", before, after)
			}
		})
	}
}

func TestCandidateSuccessTransfersOwnershipAndShallowCopiesShareDiscard(t *testing.T) {
	before := candidateRoutines()
	raw := config.DefaultRawConfig()
	raw.Proxy = []map[string]any{anyTLSCandidate("owned")}
	raw.ProxyProvider = map[string]map[string]any{"inline": {"type": "inline", "payload": []map[string]any{anyTLSCandidate("subscribed")}}}
	raw.ProxyGroup = []map[string]any{{"name": "selected", "type": "select", "proxies": []string{"owned"}, "use": []string{"inline"}}}
	cfg, err := config.ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cfg.Discard(context.Background()) })
	deadline := time.Now().Add(time.Second)
	for candidateRoutines() != before+2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := candidateRoutines(); got != before+2 {
		t.Fatalf("valid candidate owns %d idle routines, want %d", got, before+2)
	}
	if err := cfg.Providers["inline"].Update(); err != nil {
		t.Fatalf("valid candidate was prematurely cancelled: %v", err)
	}
	runtimeCopy := *cfg
	if err := runtimeCopy.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := candidateRoutines(); got != before {
		t.Fatalf("Discard retained idle routines: %d != %d", got, before)
	}
	if err := cfg.Providers["inline"].Update(); err == nil {
		t.Fatal("discarded provider still accepts updates")
	}
}

func TestCandidateFailureDoesNotRetirePublishedConfiguration(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.Proxy = []map[string]any{anyTLSCandidate("active")}
	active, err := config.ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = active.Discard(context.Background()) })
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(active.Proxies, active.Providers)
	defer tunnel.UpdateProxies(oldProxies, oldProviders)
	before := candidateRoutines()
	bad := config.DefaultRawConfig()
	bad.Proxy = []map[string]any{anyTLSCandidate("failed")}
	bad.DNS.Enable, bad.DNS.NameServer = true, nil
	if _, err := config.ParseRawConfig(bad); err == nil {
		t.Fatal("invalid config succeeded")
	}
	if got := tunnel.Proxies()["active"]; got != active.Proxies["active"] {
		t.Fatal("candidate cleanup modified active proxy map")
	}
	if err := active.Providers["default"].Update(); err != nil {
		t.Fatalf("candidate cleanup cancelled active provider: %v", err)
	}
	if candidateRoutines() != before {
		t.Fatal("candidate cleanup closed active transport or leaked its own")
	}
}
