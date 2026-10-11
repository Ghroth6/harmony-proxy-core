package policy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func publicHealthCandidate(t *testing.T, group, endpoint string, lazy bool) (*policy.Engine, *config.Config) {
	t.Helper()
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nproxy-groups:\n - {name: PublicAuto, type: %s, proxies: [REJECT, DIRECT], url: '%s', expected-status: 204, interval: 1, lazy: %t}\nrules: ['MATCH,PublicAuto']\n", group, endpoint, lazy))
	plan := engine.Plan("group-health-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete {
		t.Fatalf("actual group plan: %s/%s", plan.Category, plan.Code)
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("group-health-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("actual group validation: %s/%s", receipt.Category, receipt.Code)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	return engine, cfg
}

func TestOriginalGroupHealthCheckWaitsForActivationPreservesIntervalLazyAndSelection(t *testing.T) {
	for _, group := range []string{"url-test", "fallback"} {
		t.Run(group, func(t *testing.T) {
			var requests, protected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "HEAD" || r.URL.Path != "/original-check" {
					t.Error("original URLTest method/path changed")
				}
				requests.Add(1)
				// Pinned URLTest uses a zero-millisecond delay as unknown. Give
				// the real fixture response a measurable delay before selection;
				// an arbitrarily fast loopback reply is not a known delay sample.
				time.Sleep(5 * time.Millisecond)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(server.Close)
			engine, cfg := publicHealthCandidate(t, group, server.URL+"/original-check", true)
			baseline := engine.ResourceAcquireCount()
			if requests.Load() != 0 {
				t.Fatal("pure Plan/Validate/Build performed a health request")
			}
			activatePublicPolicy(t, cfg, []string{}, &protected, true)
			if requests.Load() != 0 {
				t.Fatal("publication opened group health admission")
			}
			if err := executor.ActivateMobilePolicy(cfg); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for requests.Load() < 1 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if requests.Load() != 1 || protected.Load() == 0 {
				t.Fatal("explicit activation did not run the original protected health check")
			}
			// Arrival at the peer precedes URLTest's result publication. Wait
			// for that public result before reading Now: URLTest deliberately
			// caches its automatic choice for ten seconds, including a choice
			// made while the initial health measurements are still pending.
			for (cfg.Proxies["DIRECT"].LastDelayForTestUrl(server.URL+"/original-check") == 0xffff || cfg.Proxies["REJECT"].AliveForTestUrl(server.URL+"/original-check")) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			selected := cfg.Proxies["PublicAuto"].Adapter().(interface{ Now() string })
			if selected.Now() != "DIRECT" {
				t.Fatal("real original health result did not select the healthy member")
			}
			time.Sleep(1150 * time.Millisecond)
			if requests.Load() != 1 {
				t.Fatal("lazy original group refreshed without being touched")
			}
			cfg.Providers["PublicAuto"].Touch()
			deadline = time.Now().Add(2 * time.Second)
			for requests.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if requests.Load() != 2 {
				t.Fatal("original touched group did not refresh at its configured interval")
			}
			cfg.CancelMobilePolicyServices()
			wait, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := cfg.WaitMobilePolicyServices(wait); err != nil {
				t.Fatal(err)
			}
			stopped := requests.Load()
			time.Sleep(1100 * time.Millisecond)
			if requests.Load() != stopped || engine.ResourceAcquireCount() != baseline {
				t.Fatal("retired health timer reopened or was miscounted as a resource download")
			}
		})
	}
}

func TestOriginalGroupHealthCheckRetirementClosesAndJoinsActualPendingRead(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{})
	closed := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		_, err = http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			closed <- err
			return
		}
		close(seen)
		_, err = conn.Read(make([]byte, 1))
		closed <- err
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	_, cfg := publicHealthCandidate(t, "fallback", "http://"+listener.Addr().String()+"/pending", false)
	var protected atomic.Int32
	activatePublicPolicy(t, cfg, []string{}, &protected)
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("actual group health request did not reach the pending peer")
	}
	cfg.CancelMobilePolicyServices()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = cfg.WaitMobilePolicyServices(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("pending physical request was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("clean wait left a physical group-health socket open")
	}
}
