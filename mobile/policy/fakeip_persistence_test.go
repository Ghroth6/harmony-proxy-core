package policy_test

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
)

func TestOriginalFakeIPPersistencePreparesWithoutFilesAndReopensBothPools(t *testing.T) {
	root := t.TempDir()
	raw := []byte(`ipv6: true
profile: {store-fake-ip: true}
dns:
 enable: true
 ipv6: true
 enhanced-mode: fake-ip
 fake-ip-range: 198.18.0.1/16
 fake-ip-range6: fdfe:dcba:9876::1/64
 nameserver: [192.0.2.53]
 default-nameserver: [192.0.2.53]
 fallback-filter: {geoip: false}
rules: ['MATCH,REJECT']
`)
	var original [2]string
	for round, name := range []string{"initial", "reopened"} {
		t.Run(name, func(t *testing.T) {
			engine, err := policy.NewEngine(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = engine.Close() })
			plan := engine.Plan("fakeip-persistence-plan", raw, nil)
			platform := publicPlatform()
			platform.RuntimeOptions.DNS, platform.RuntimeOptions.IPv6 = true, true
			platform.PlatformPolicy.AddressFamily = "dual"
			platform.TunPolicy.IPv6 = &contract.IPv6Policy{Address: "fd00:111::1", PrefixLength: 126, Route: "::", RoutePrefixLength: 0}
			platform.TunPolicy.DNSServers = []string{"10.111.0.2", "fd00:111::2"}
			prepared, err := contract.Seal(plan.InputDigest, nil, platform, nil)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Category != "planned" || !plan.ResourcesComplete {
				t.Fatalf("original persistence must plan: %s", plan.Code)
			}
			if receipt := engine.Validate("fakeip-persistence-validate", raw, prepared); receipt.Category != "pass" {
				t.Fatalf("original persistence must validate: %s", receipt.Code)
			}
			cfg, err := engine.BuildCandidate(raw, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.Close(); err == nil {
				t.Fatal("prepared candidate must pin its actual trusted state root")
			}
			if round == 0 {
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 {
					t.Fatal("pure Plan/Validate/Build must not create persistent state")
				}
			}
			var protected atomic.Int32
			ctx, generation := activatePublicPolicy(t, cfg, []string{"192.0.2.53"}, &protected)
			if err = engine.Close(); err == nil {
				t.Fatal("activated candidate must keep its trusted root pinned")
			}
			for family, qtype := range []uint16{D.TypeA, D.TypeAAAA} {
				for _, domain := range []string{"documentation-a.example.", "documentation-b.example."} {
					message := new(D.Msg)
					message.SetQuestion(domain, qtype)
					response, err := cfg.MobileDNSService().ServeMsg(ctx, message)
					if err != nil || len(response.Answer) != 1 {
						t.Fatalf("real scoped DNS persistence lookup failed: %v", err)
					}
					value := response.Answer[0].String()
					if domain == "documentation-a.example." {
						if round == 0 {
							original[family] = value
						} else if value != original[family] {
							t.Fatal("reopened IPv4/IPv6 mapping changed")
						}
					}
				}
			}
			if protected.Load() != 0 || engine.ResourceAcquireCount() != "0" {
				t.Fatal("fake-IP answers and state restore must require no upstream DNS or resource GET")
			}
			cfg.CancelMobilePolicyServices()
			tunnel.CancelForwarding()
			wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err = tunnel.StopForwarding(wait); err != nil {
				t.Fatal(err)
			}
			if err = cfg.WaitMobilePolicyServices(wait); err != nil {
				t.Fatal(err)
			}
			if err = executor.RetireConfig(wait); err != nil {
				t.Fatal(err)
			}
			cancel()
			if engine.QueryResources("fakeip-stopped-query", generation).Category != "absent" {
				t.Fatal("closed state DB must retire the actual policy owner")
			}
			if err = engine.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDiscardedPersistentCandidateReleasesRootWithoutOpeningState(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	raw := []byte("ipv6: false\nprofile: {store-fake-ip: true}\ndns:\n enable: true\n ipv6: false\n enhanced-mode: fake-ip\n nameserver: [192.0.2.53]\n fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n")
	platform := publicPlatform()
	platform.RuntimeOptions.DNS = true
	platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
	prepared, err := contract.Seal(contract.Digest(raw), nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Close() == nil {
		t.Fatal("unactivated persistent candidate must pin the trusted root")
	}
	if err = candidate.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("discard must close the pure owner without creating a DB or directory")
	}
}
