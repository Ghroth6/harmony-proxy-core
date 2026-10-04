package provider

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type retirementAdapter struct {
	*outbound.Base
	block    atomic.Bool
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	once     sync.Once
	calls    atomic.Int32
}

func (a *retirementAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	a.calls.Add(1)
	if a.block.Load() {
		a.once.Do(func() { close(a.started) })
		<-ctx.Done()
		close(a.canceled)
		<-a.release // A driver may acknowledge cancellation later than the caller.
		return nil, ctx.Err()
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(c, a), nil
}

func newRetirementProxy() (*adapter.Proxy, *retirementAdapter) {
	a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Direct}), started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	return adapter.NewProxy(a), a
}

func awaitRetirement(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not reach expected boundary")
	}
}

func TestHealthCheckRetirementWaitsForDialAndSuppressesLateResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	p, dial := newRetirementProxy()
	if _, err := p.URLTest(context.Background(), server.URL, nil); err != nil {
		t.Fatal(err)
	}
	prior := p.DelayHistory()[0]
	dial.block.Store(true)
	hc := NewHealthCheck([]C.Proxy{p}, server.URL, 5000, 0, false, nil)
	pd, err := NewCompatibleProvider("retiring", []C.Proxy{p}, hc)
	if err != nil {
		t.Fatal(err)
	}
	var events atomic.Int32
	unsubscribe := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
		if e.Proxy == p {
			events.Add(1)
		}
	})
	defer unsubscribe()
	finished := make(chan struct{})
	go func() { pd.HealthCheck(); close(finished) }()
	awaitRetirement(t, dial.started)
	pd.Cancel()
	awaitRetirement(t, dial.canceled)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pd.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("premature retirement: %v", err)
	}
	close(dial.release)
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitRetirement(t, finished)
	if history := p.DelayHistory(); len(history) != 1 || history[0] != prior || !p.AliveForTestUrl(server.URL) || events.Load() != 0 {
		t.Fatalf("retired check published: history=%v alive=%v events=%d", history, p.AliveForTestUrl(server.URL), events.Load())
	}
	before := dial.calls.Load()
	pd.HealthCheck()
	pd.RegisterHealthCheckTask("http://other.invalid", nil, "", 1)
	if err := pd.Initial(); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired provider restarted: %v", err)
	}
	if err := pd.Update(); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired provider updated: %v", err)
	}
	if dial.calls.Load() != before {
		t.Fatal("retired provider admitted a check")
	}
	if err := pd.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHealthCheckRepeatedInitialAndCallbackCancellationJoin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	p, dial := newRetirementProxy()
	hc := NewHealthCheck([]C.Proxy{p}, server.URL, 1000, 1, false, nil)
	pd, err := NewCompatibleProvider("repeated", []C.Proxy{p}, hc)
	if err != nil {
		t.Fatal(err)
	}
	callbackStarted, releaseCallback := make(chan struct{}), make(chan struct{})
	unsubscribe := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
		if e.Proxy != p {
			return
		}
		pd.Cancel() // Must not call a subscriber with the health-check lock held.
		close(callbackStarted)
		<-releaseCallback
	})
	defer unsubscribe()
	for i := 0; i < 20; i++ {
		if err := pd.Initial(); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	awaitRetirement(t, callbackStarted)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pd.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("callback not joined: %v", err)
	}
	close(releaseCallback)
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if dial.calls.Load() != 1 {
		t.Fatalf("duplicate initial checks: %d", dial.calls.Load())
	}
	if err := pd.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHealthCheckTimeoutStillPublishesFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	p, _ := newRetirementProxy()
	hc := NewHealthCheck([]C.Proxy{p}, server.URL, 20, 0, false, nil)
	pd, err := NewCompatibleProvider("active", []C.Proxy{p}, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	var events atomic.Int32
	unsubscribe := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
		if e.Proxy == p {
			events.Add(1)
		}
	})
	defer unsubscribe()
	pd.HealthCheck()
	if len(p.DelayHistory()) != 1 || p.AliveForTestUrl(server.URL) || events.Load() != 1 {
		t.Fatal("request deadline was incorrectly treated as configuration retirement")
	}
}

type retirementVehicle struct {
	path                       string
	started, canceled, release chan struct{}
	writes                     atomic.Int32
}

func (v *retirementVehicle) Read(ctx context.Context, _ utils.HashType) ([]byte, utils.HashType, error) {
	close(v.started)
	<-ctx.Done()
	close(v.canceled)
	<-v.release
	buf := []byte("late proxies")
	return buf, utils.MakeHash(buf), nil // Deliberately ignore cancellation.
}
func (v *retirementVehicle) Write([]byte) error { v.writes.Add(1); return nil }
func (v *retirementVehicle) Path() string       { return v.path }
func (*retirementVehicle) Url() string          { return "http://example.invalid" }
func (*retirementVehicle) Proxy() string        { return "" }
func (*retirementVehicle) Type() P.VehicleType  { return P.HTTP }

func TestProxySetRetirementCancelsFetcherAndHealthBeforeWaiting(t *testing.T) {
	p, dial := newRetirementProxy()
	dial.block.Store(true)
	hc := NewHealthCheck([]C.Proxy{p}, "http://example.invalid", 5000, 0, false, nil)
	v := &retirementVehicle{path: filepath.Join(t.TempDir(), "proxies.yaml"), started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	pd, err := NewProxySetProvider("set", 0, nil, func([]byte) ([]C.Proxy, error) { return []C.Proxy{p}, nil }, v, hc)
	if err != nil {
		t.Fatal(err)
	}
	checkDone, updateDone := make(chan struct{}), make(chan error, 1)
	go func() { pd.HealthCheck(); close(checkDone) }()
	go func() { updateDone <- pd.Update() }()
	awaitRetirement(t, dial.started)
	awaitRetirement(t, v.started)
	pd.Cancel()
	awaitRetirement(t, dial.canceled)
	awaitRetirement(t, v.canceled)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pd.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished work was discarded: %v", err)
	}
	close(dial.release)
	close(v.release)
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitRetirement(t, checkDone)
	if err := <-updateDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("late provider update succeeded: %v", err)
	}
	if pd.Version() != 0 || pd.Count() != 0 || v.writes.Load() != 0 {
		t.Fatal("late provider result was committed")
	}
	if err := pd.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoppedForwardingPreservesHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	p, _ := newRetirementProxy()
	hc := NewHealthCheck([]C.Proxy{p}, server.URL, 1000, 0, false, nil)
	pd, err := NewCompatibleProvider("management", []C.Proxy{p}, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	forwarding.Enable()
	if err := forwarding.Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	forwarding.Cancel()
	if err := forwarding.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	pd.HealthCheck()
	if len(p.DelayHistory()) != 1 || !p.AliveForTestUrl(server.URL) {
		t.Fatal("stopping forwarding disabled configuration health checks")
	}
}
