package policy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

const redirectOld = "payload:\n - DOMAIN-SUFFIX,documentation.example\n"
const redirectNew = "payload:\n - DOMAIN-SUFFIX,updated.example\n"

func publicPeriodicCandidate(t *testing.T, endpoint string) (*policy.Engine, *config.Config, contract.Resource, context.Context, uint64) {
	t.Helper()
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
	input := []byte(strings.ReplaceAll(strings.ReplaceAll(providerPolicy, "https://resources.example/rules.yaml", endpoint), "interval: 86400", "interval: 1, proxy: DIRECT, header: {X-Private-Fixture: [documentation-only], Authorization: [documentation-only], Cookie: [documentation-only]}"))
	plan := engine.Plan("redirect-plan", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 {
		t.Fatalf("actual resource plan: %s/%s", plan.Category, plan.Code)
	}
	resource := savePublicResource(t, root, plan.Requirements[0], []byte(redirectOld))
	platform := publicPlatform()
	platform.RuntimeOptions.ResourceDownloads = true
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("redirect-validate", input, prepared); receipt.Category != "pass" {
		t.Fatalf("actual resource validation: %s/%s", receipt.Category, receipt.Code)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var protected atomic.Int32
	ctx, generation := activatePublicPolicy(t, cfg, []string{}, &protected)
	return engine, cfg, resource, ctx, generation
}

func awaitPublicPeriodicAttempt(t *testing.T, engine *policy.Engine, cfg *config.Config, ctx context.Context, generation uint64) policy.ResourcesReceipt {
	t.Helper()
	if err := cfg.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var observed policy.ResourcesReceipt
	for time.Now().Before(deadline) {
		observed = engine.QueryResources("redirect-observe", generation)
		if len(observed.Events) > 0 {
			last := observed.Events[len(observed.Events)-1].Stage
			if last == "adopted" || last == "failed" {
				cfg.CancelMobilePolicyServices()
				wait, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := cfg.WaitMobilePolicyServices(wait); err != nil {
					t.Fatal(err)
				}
				return observed
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("actual declared interval did not finish its first request")
	return observed
}

func TestOriginalResourceRedirectStripsDeclaredHeadersAcrossAndAfterOriginChangeAndCountsEachGET(t *testing.T) {
	var requests, leaks atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" {
			t.Error("resource redirect changed the actual method")
		}
		if r.Header.Get("X-Private-Fixture") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			leaks.Add(1)
		}
		if r.URL.Path == "/cross" {
			http.Redirect(w, r, "/complete", http.StatusFound)
			return
		}
		fmt.Fprint(w, redirectNew)
	}))
	t.Cleanup(destination.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Private-Fixture") != "documentation-only" {
			t.Error("initial declared source header was lost")
		}
		http.Redirect(w, r, destination.URL+"/cross", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	engine, cfg, _, ctx, generation := publicPeriodicCandidate(t, origin.URL+"/declared")
	baseline, _ := strconv.ParseUint(engine.ResourceAcquireCount(), 10, 64)
	if requests.Load() != 0 {
		t.Fatal("preparation or publication acquired a redirect source")
	}
	observed := awaitPublicPeriodicAttempt(t, engine, cfg, ctx, generation)
	if leaks.Load() != 0 {
		t.Fatal("declared credentials were forwarded after an origin change")
	}
	if requests.Load() != 3 || observed.ResourceAcquireCount != strconv.FormatUint(baseline+3, 10) {
		t.Fatal("each actual redirect GET must have its own acquisition attempt count")
	}
	if len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest != contract.Digest([]byte(redirectNew)) {
		t.Fatal("complete final response was not saved and adopted by the actual provider")
	}
}

func TestOriginalResourceRedirectLimitAndPartialResponseRetainActualOldStrategy(t *testing.T) {
	for _, sample := range []struct {
		name      string
		redirect  int
		status    int
		adopt     bool
		requests  uint64
		truncated bool
	}{
		{"five-hops", 5, 200, true, 6, false},
		{"sixth-hop-denied", 6, 200, false, 6, false},
		{"partial-206-denied", 0, 206, false, 1, false},
		{"truncated-200-denied", 0, 200, false, 1, true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("X-Private-Fixture") != "documentation-only" {
					t.Error("same-origin redirect must preserve declared source headers")
				}
				step, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
				if step < sample.redirect {
					http.Redirect(w, r, "/"+strconv.Itoa(step+1), http.StatusFound)
					return
				}
				if sample.truncated {
					w.Header().Set("Content-Length", strconv.Itoa(len(redirectNew)+8))
				}
				w.WriteHeader(sample.status)
				fmt.Fprint(w, redirectNew)
			}))
			t.Cleanup(server.Close)
			engine, cfg, initial, ctx, generation := publicPeriodicCandidate(t, server.URL+"/0")
			baseline, _ := strconv.ParseUint(engine.ResourceAcquireCount(), 10, 64)
			observed := awaitPublicPeriodicAttempt(t, engine, cfg, ctx, generation)
			if requests.Load() != int32(sample.requests) || observed.ResourceAcquireCount != strconv.FormatUint(baseline+sample.requests, 10) {
				t.Fatal("redirect bound or actual GET count was not enforced")
			}
			expected := initial.ContentDigest
			if sample.adopt {
				expected = contract.Digest([]byte(redirectNew))
			}
			if len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest != expected {
				t.Fatal("unsuccessful redirect or partial response changed the adopted immutable revision")
			}
			matched, _ := cfg.Rules[0].Match(&C.Metadata{Host: "a.documentation.example"}, C.RuleMatchHelper{})
			if matched == sample.adopt {
				t.Fatal("actual rule-provider strategy disagrees with the recorded revision")
			}
		})
	}
}

func TestOriginalResourceRedirectCancellationJoinsActualPendingBodyAndRetainsOldStrategy(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{})
	closed := make(chan error, 1)
	done := make(chan struct{})
	var requests atomic.Int32
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = http.ReadRequest(bufio.NewReader(conn)); err != nil {
			closed <- err
			return
		}
		requests.Add(1)
		if _, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n%s", redirectNew); err != nil {
			closed <- err
			return
		}
		close(seen)
		_, err = conn.Read(make([]byte, 1))
		closed <- err
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "http://"+listener.Addr().String()+"/pending-body", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	engine, cfg, initial, ctx, generation := publicPeriodicCandidate(t, origin.URL)
	baseline, _ := strconv.ParseUint(engine.ResourceAcquireCount(), 10, 64)
	if err := cfg.ActivateMobilePolicyResources(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("declared resource redirect did not reach the actual pending body")
	}
	cfg.CancelMobilePolicyServices()
	deadline := time.Now().Add(time.Second)
	var observed policy.ResourcesReceipt
	for time.Now().Before(deadline) {
		observed = engine.QueryResources("redirect-cancelled", generation)
		if len(observed.Events) > 0 && observed.Events[len(observed.Events)-1].Stage == "cancelled" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if observed.ResourceAcquireCount != strconv.FormatUint(baseline+2, 10) || requests.Load() != 2 || len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest != initial.ContentDigest {
		t.Fatal("cancellation lost the actual GET count or changed the initial resource version")
	}
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := cfg.WaitMobilePolicyServices(wait); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("pending physical resource body stayed readable after cleanup")
		}
	case <-time.After(time.Second):
		t.Fatal("clean resource wait left its real redirected socket open")
	}
}

func TestOriginalResourceRedirectCannotDowngradeVerifiedTLS(t *testing.T) {
	var tlsRequests, plainRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainRequests.Add(1)
		fmt.Fprint(w, redirectNew)
	}))
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsRequests.Add(1)
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	t.Cleanup(secure.Close)
	if err := ca.AddCertificate(string(secure.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.ResetCertificate)
	engine, cfg, initial, ctx, generation := publicPeriodicCandidate(t, secure.URL)
	baseline, _ := strconv.ParseUint(engine.ResourceAcquireCount(), 10, 64)
	observed := awaitPublicPeriodicAttempt(t, engine, cfg, ctx, generation)
	if tlsRequests.Load() != 1 || plainRequests.Load() != 0 || observed.ResourceAcquireCount != strconv.FormatUint(baseline+1, 10) {
		t.Fatal("verified TLS redirect sent an actual plaintext request")
	}
	if len(observed.Adopted) != 1 || observed.Adopted[0].ContentDigest != initial.ContentDigest {
		t.Fatal("TLS downgrade changed the original provider strategy")
	}
}
