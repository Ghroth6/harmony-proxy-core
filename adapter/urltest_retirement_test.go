package adapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type retiredTestDialer struct {
	*outbound.Base
	started, canceled, release chan struct{}
	calls                      atomic.Int32
}

func (d *retiredTestDialer) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	d.calls.Add(1)
	close(d.started)
	<-ctx.Done()
	close(d.canceled)
	<-d.release
	return nil, ctx.Err()
}

func waitTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("URLTest did not reach expected boundary")
	}
}

func TestRetireManualAndGroupURLTests(t *testing.T) {
	for _, group := range []bool{false, true} {
		name := "manual"
		if group {
			name = "group"
		}
		t.Run(name, func(t *testing.T) {
			d := &retiredTestDialer{Base: outbound.NewBase(outbound.BaseOption{Name: "retired", Type: C.Direct}), started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
			p := adapter.NewProxy(d)
			var events atomic.Int32
			unsubscribe := adapter.SubscribeURLTests(func(e adapter.URLTestEvent) {
				if e.Proxy == p {
					events.Add(1)
				}
			})
			defer unsubscribe()
			call := func() error { _, err := p.URLTest(context.Background(), "http://example.invalid", nil); return err }
			if group {
				hc := provider.NewHealthCheck([]C.Proxy{p}, "", 0, 0, false, nil)
				pd, err := provider.NewCompatibleProvider("group-members", []C.Proxy{p}, hc)
				if err != nil {
					t.Fatal(err)
				}
				defer pd.Close()
				g := outboundgroup.NewGroupBase(outboundgroup.GroupBaseOption{Name: "test-group", Providers: []P.ProxyProvider{pd}})
				call = func() error { _, err := g.URLTest(context.Background(), "http://example.invalid", nil); return err }
			}
			result := make(chan error, 1)
			go func() { result <- call() }()
			waitTestSignal(t, d.started)
			p.CancelURLTests()
			waitTestSignal(t, d.canceled)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := p.WaitURLTests(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unfinished dial discarded: %v", err)
			}
			close(d.release)
			if err := p.WaitURLTests(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("retired URLTest succeeded")
			}
			if len(p.DelayHistory()) != 0 || !p.AliveForTestUrl("http://example.invalid") || events.Load() != 0 {
				t.Fatal("retired URLTest published a result")
			}
			if _, err := p.URLTest(context.Background(), "http://example.invalid", nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("retired object admitted another test: %v", err)
			}
			if d.calls.Load() != 1 {
				t.Fatal("retired object dialed again")
			}
			p.CancelURLTests()
		})
	}
}

func TestRetiredProxyWrapperDoesNotRetireReusedTransportWrapper(t *testing.T) {
	d := &eventAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "shared", Type: C.Direct}), dialErr: errors.New("ordinary unreachable node")}
	old, current := adapter.NewProxy(d), adapter.NewProxy(d)
	old.CancelURLTests()
	if err := old.WaitURLTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _ = current.URLTest(context.Background(), "http://example.invalid", nil)
	if len(old.DelayHistory()) != 0 || len(current.DelayHistory()) != 1 {
		t.Fatal("retirement escaped its proxy wrapper")
	}
}

func TestURLTestComposesOwnerCommitGuards(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	p := newEventProxy("active", nil)
	ctx := adapter.WithURLTestCommitGuard(context.Background(), func(func()) bool { return false })
	ctx = adapter.WithURLTestCommitGuard(ctx, func(commit func()) bool { commit(); return true })
	if _, err := p.URLTest(ctx, server.URL, nil); err != nil {
		t.Fatal(err)
	}
	if len(p.DelayHistory()) != 0 {
		t.Fatal("new guard replaced parent retirement fence")
	}
}
