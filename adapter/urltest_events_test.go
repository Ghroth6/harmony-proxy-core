package adapter_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type eventAdapter struct {
	*outbound.Base
	dialErr error
}

func (a *eventAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if a.dialErr != nil {
		return nil, a.dialErr
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(c, a), nil
}

func newEventProxy(providerName string, dialErr error) *adapter.Proxy {
	return adapter.NewProxy(&eventAdapter{
		Base:    outbound.NewBase(outbound.BaseOption{Name: "same-node", ProviderName: providerName, Type: C.Direct}),
		dialErr: dialErr,
	})
}

func TestURLTestEventsContainSettledResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected method %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialErr := errors.New("test dial rejected")
	accepted, _ := utils.NewUnsignedRanges[uint16]("204")
	rejected, _ := utils.NewUnsignedRanges[uint16]("200")
	for _, tc := range []struct {
		name     string
		url      string
		expected utils.IntRanges[uint16]
		dialErr  error
		status   int
		success  bool
		wantErr  bool
	}{
		{"success", server.URL, accepted, nil, 204, true, false},
		{"http-status-rejected", server.URL, rejected, nil, 204, false, false},
		{"dial-error", server.URL, accepted, dialErr, 0, false, true},
		{"invalid-url", "unsupported://example", nil, nil, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newEventProxy("subscription-A", tc.dialErr)
			var seen []adapter.URLTestEvent
			cancel := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
				if e.Proxy != p {
					return
				}
				seen = append(seen, e)
				// Reading inside a callback must not deadlock, and must see this
				// result in both histories rather than the previous state.
				global := p.DelayHistory()
				perURL := p.DelayHistoryForTestUrl(tc.url)
				if len(global) != 1 || len(perURL) != 1 || perURL[0].Time != e.Time || perURL[0].Delay != e.Delay {
					t.Errorf("history not committed before event: %#v / %#v / %#v", global, perURL, e)
				}
				if p.AliveForTestUrl(tc.url) != e.Succeeded {
					t.Error("alive state not settled")
				}
			})
			defer cancel()
			delay, err := p.URLTest(context.Background(), tc.url, tc.expected)
			if len(seen) != 1 {
				t.Fatalf("received %d events", len(seen))
			}
			e := seen[0]
			if e.URL != tc.url || e.Name != "same-node" || e.ProviderName != "subscription-A" || e.StatusCode != tc.status || e.Succeeded != tc.success {
				t.Fatalf("wrong event identity/result: %#v", e)
			}
			if (e.Err != nil) != tc.wantErr || e.Err != err {
				t.Fatalf("error not preserved: %v / %v", e.Err, err)
			}
			if tc.success && e.Delay != delay || !tc.success && e.Delay != 0 {
				t.Fatalf("invalid delay: %d / %d", e.Delay, delay)
			}
		})
	}
}

func TestURLTestEventsIncludeProviderHealthChecksAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	p := newEventProxy("subscription-A", nil)
	hc := provider.NewHealthCheck([]C.Proxy{p}, server.URL, 1000, 0, false, nil)
	pd, err := provider.NewCompatibleProvider("automatic-check-owner", []C.Proxy{p}, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	var events atomic.Int64
	cancel := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
		if e.Proxy == p {
			if !e.Succeeded || e.ProviderName != "subscription-A" {
				t.Error("invalid health-check event")
			}
			events.Add(1)
		}
	})
	pd.HealthCheck()
	if events.Load() != 1 {
		t.Fatal("provider health check did not use the event path")
	}
	cancel()
	_, _ = p.URLTest(context.Background(), server.URL, nil)
	if events.Load() != 1 {
		t.Fatal("cancelled observer still received URL results")
	}
}

func TestURLTestConcurrentHistoriesAndObjectIdentity(t *testing.T) {
	first := newEventProxy("provider-A", errors.New("offline"))
	second := newEventProxy("provider-B", errors.New("offline"))
	var mu sync.Mutex
	counts := map[C.Proxy]int{}
	cancel := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
		mu.Lock()
		counts[e.Proxy]++
		mu.Unlock()
		if e.Name != "same-node" || e.ProviderName != e.Proxy.ProxyInfo().ProviderName || e.Succeeded || e.Err == nil {
			t.Error("ambiguous or incomplete concurrent event")
		}
		_ = e.Proxy.DelayHistory()
		_ = e.Proxy.ExtraDelayHistories()
		_ = e.Proxy.LastDelayForTestUrl(e.URL)
	})
	defer cancel()
	var wg sync.WaitGroup
	const checks = 32
	for _, p := range []*adapter.Proxy{first, second} {
		for i := 0; i < checks; i++ {
			wg.Add(1)
			go func(p *adapter.Proxy) {
				defer wg.Done()
				_, _ = p.URLTest(context.Background(), "http://example.invalid", nil)
			}(p)
		}
	}
	wg.Wait()
	for _, p := range []*adapter.Proxy{first, second} {
		if counts[p] != checks || len(p.DelayHistory()) != 10 || len(p.DelayHistoryForTestUrl("http://example.invalid")) != 10 {
			t.Fatalf("lost events or unbounded history: events=%d history=%d", counts[p], len(p.DelayHistory()))
		}
	}
}
