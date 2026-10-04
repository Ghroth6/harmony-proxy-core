package executor

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	AP "github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener/inner"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"
)

type retirementProvider struct {
	P.ProxyProvider
	name      string
	proxies   []C.Proxy
	cancelled atomic.Bool
	initial   atomic.Int32
	done      chan struct{}
}

func (p *retirementProvider) Name() string               { return p.name }
func (p *retirementProvider) Proxies() []C.Proxy         { return p.proxies }
func (p *retirementProvider) VehicleType() P.VehicleType { return P.Compatible }
func (p *retirementProvider) Type() P.ProviderType       { return P.Proxy }
func (p *retirementProvider) Initial() error             { p.initial.Add(1); return nil }
func (p *retirementProvider) Cancel()                    { p.cancelled.Store(true) }
func (p *retirementProvider) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type retirementAdapter struct {
	*outbound.Base
	calls    atomic.Int32
	closeErr error
}

func (a *retirementAdapter) Close() error { a.calls.Add(1); return a.closeErr }

type historicalRetirementAdapter struct {
	*retirementAdapter
	connection net.Conn
}

func (a *historicalRetirementAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return outbound.NewConn(a.connection, a), nil
}

func TestConfigRetirementIncludesHistoricalProviderConnections(t *testing.T) {
	next := retirementFixture(t)
	left, right := net.Pipe()
	defer right.Close()
	raw := &historicalRetirementAdapter{
		retirementAdapter: &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "historical", Type: C.Direct})},
		connection:        left,
	}
	old := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(raw))
	defer old.Close()
	newRaw := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "current", Type: C.Direct})}
	current := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(newRaw))
	defer current.Close()
	pd, err := AP.NewProxySetProvider("owned", 0, []map[string]any{{"name": "initial"}}, func(data []byte) ([]C.Proxy, error) {
		if string(data) == "next" {
			return []C.Proxy{current}, nil
		}
		return []C.Proxy{old}, nil
	}, resource.NewFileVehicle(filepath.Join(t.TempDir(), "nodes.yaml")), AP.NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	tunnel.UpdateProxies(nil, map[string]P.ProxyProvider{"owned": pd})
	conn, err := old.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if raw.calls.Load() != 0 {
		t.Fatal("provider refresh interrupted an existing connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ApplyConfigContext(ctx, next, false); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("old configuration still has a live historical connection")
	}
	if raw.calls.Load() != 1 || newRaw.calls.Load() != 1 {
		t.Fatal("config retirement missed historical or current provider adapters")
	}
}

func retirementFixture(t *testing.T) *config.Config {
	t.Helper()
	oldProxies, oldProviders, oldRules := tunnel.Proxies(), tunnel.Providers(), tunnel.RuleProviders()
	oldInner := inner.GetTunnel()
	oldCandidate := appliedCandidate
	appliedCandidate = nil
	retiringConfig = nil
	t.Cleanup(func() {
		tunnel.UpdateProxies(oldProxies, oldProviders)
		tunnel.UpdateRules(nil, nil, oldRules)
		inner.New(oldInner)
		retiringConfig = nil
		appliedCandidate = oldCandidate
		tunnel.OnRunning()
	})
	cfg, err := ParseWithBytes([]byte("mode: direct\ndns:\n  enable: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfigPublicationTransfersCandidateOwnership(t *testing.T) {
	next := retirementFixture(t)
	runtimeCopy := *next
	if err := ApplyConfigContext(context.Background(), &runtimeCopy, false); err != nil {
		t.Fatal(err)
	}
	if err := next.Discard(context.Background()); !errors.Is(err, configresources.ErrTransferred) {
		t.Fatalf("published candidate Discard = %v", err)
	}
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatalf("same-object reapply: %v", err)
	}
}

func TestDiscardedCandidateRejectedBeforeRetiringActiveConfiguration(t *testing.T) {
	next := retirementFixture(t)
	if err := next.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "active", Type: C.Direct})}
	p := &retirementProvider{name: "active", proxies: []C.Proxy{adapter.NewProxy(a)}, done: make(chan struct{})}
	tunnel.UpdateProxies(map[string]C.Proxy{"active": p.proxies[0]}, map[string]P.ProxyProvider{"active": p})
	if err := ApplyConfigContext(context.Background(), next, false); !errors.Is(err, configresources.ErrCleanupStarted) {
		t.Fatalf("Apply discarded candidate = %v", err)
	}
	if p.cancelled.Load() || a.calls.Load() != 0 || tunnel.Providers()["active"] != p {
		t.Fatal("rejected candidate retired active configuration")
	}
}

func TestRetiredParsedCandidateCannotReplaceCurrentConfiguration(t *testing.T) {
	next := retirementFixture(t)
	before := anyTLSIdleRoutines()
	first, err := ParseWithBytes([]byte("proxies:\n  - name: owned\n    type: anytls\n    server: 127.0.0.1\n    port: 443\n    password: retirement-test\n"))
	if err != nil {
		t.Fatal(err)
	}
	copyOfFirst := *first
	if err := ApplyConfigContext(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	if anyTLSIdleRoutines() != before+1 {
		t.Fatal("first configuration did not create its real AnyTLS idle routine")
	}
	if err := ApplyConfigContext(context.Background(), &copyOfFirst, false); err != nil {
		t.Fatalf("current shallow copy rejected: %v", err)
	}
	if anyTLSIdleRoutines() != before+1 {
		t.Fatal("same-candidate reapply closed its transport")
	}
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if anyTLSIdleRoutines() != before {
		t.Fatal("replacement did not close old AnyTLS transport")
	}
	for _, stale := range []*config.Config{first, &copyOfFirst} {
		if err := ApplyConfigContext(context.Background(), stale, false); !errors.Is(err, configresources.ErrRetired) {
			t.Fatalf("retired candidate Apply = %v", err)
		}
		if tunnel.Proxies()["GLOBAL"] != next.Proxies["GLOBAL"] {
			t.Fatal("stale candidate changed current map")
		}
		if err := next.Providers[AP.ReservedName].Update(); err != nil {
			t.Fatalf("rejected stale candidate cancelled current provider: %v", err)
		}
	}
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitRetirementRejectsParsedCandidateReapplication(t *testing.T) {
	_ = retirementFixture(t)
	before := anyTLSIdleRoutines()
	first, err := ParseWithBytes([]byte("proxies:\n  - name: owned\n    type: anytls\n    server: 127.0.0.1\n    port: 443\n    password: retirement-test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfigContext(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if anyTLSIdleRoutines() != before {
		t.Fatal("explicit retirement retained AnyTLS routine")
	}
	if err := ApplyConfigContext(context.Background(), first, false); !errors.Is(err, configresources.ErrRetired) {
		t.Fatalf("Apply after RetireConfig = %v", err)
	}
	if len(tunnel.Proxies()) != 0 || inner.GetTunnel() != nil {
		t.Fatal("retired candidate was republished")
	}
}

func TestRetirementTimeoutRejectsSameParsedCandidate(t *testing.T) {
	first := retirementFixture(t)
	p := &retirementProvider{name: "blocked", done: make(chan struct{})}
	first.Providers[p.name] = p
	if err := ApplyConfigContext(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := RetireConfig(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retirement = %v", err)
	}
	if !p.cancelled.Load() {
		t.Fatal("timeout occurred before cancellation")
	}
	if err := ApplyConfigContext(context.Background(), first, false); !errors.Is(err, configresources.ErrRetired) {
		t.Fatalf("same candidate after retirement timeout = %v", err)
	}
	close(p.done)
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfigContext(context.Background(), first, false); !errors.Is(err, configresources.ErrRetired) {
		t.Fatalf("retired candidate after eventual cleanup = %v", err)
	}
}

func anyTLSIdleRoutines() int {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "github.com/metacubex/mihomo/transport/anytls/util.StartRoutine.func1(")
}

func TestConfigRetirementCancelsAllBeforeWaitAndBlocksPublication(t *testing.T) {
	next := retirementFixture(t)
	a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "old", Type: C.Direct})}
	p := &retirementProvider{name: "slow", proxies: []C.Proxy{adapter.NewProxy(a)}, done: make(chan struct{})}
	other := &retirementProvider{name: "other", done: make(chan struct{})}
	close(other.done)
	tunnel.UpdateProxies(map[string]C.Proxy{"old": p.proxies[0]}, map[string]P.ProxyProvider{"slow": p, "other": other})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := ApplyConfigContext(ctx, next, false)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || !p.cancelled.Load() || !other.cancelled.Load() {
		t.Fatalf("missing cancel/wait barrier: %v", err)
	}
	if tunnel.Providers()["slow"] != p || a.calls.Load() != 0 {
		t.Fatal("published or closed before old task completed")
	}
	close(p.done)
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if tunnel.Providers()["slow"] == p || a.calls.Load() != 1 {
		t.Fatal("new configuration was not published after retirement")
	}
}

func TestConfigRetirementPreservesReusedProviderAndAdapterIdentity(t *testing.T) {
	next := retirementFixture(t)
	a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "shared", Type: C.Direct})}
	proxy := adapter.NewProxy(a)
	p := &retirementProvider{name: "retained", proxies: []C.Proxy{proxy}, done: make(chan struct{})}
	tunnel.UpdateProxies(map[string]C.Proxy{"alias": proxy}, map[string]P.ProxyProvider{"old-name": p})
	next.Providers["renamed"] = p
	next.Proxies["new-alias"] = adapter.NewProxy(a)
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if p.cancelled.Load() || p.initial.Load() != 0 || a.calls.Load() != 0 {
		t.Fatal("reused owner was retired or initialized twice")
	}
}

func TestConfigRetirementRetainsCloseFailureWithoutRepeatingOpaqueClose(t *testing.T) {
	next := retirementFixture(t)
	failure := errors.New("pool close uncertain")
	a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "shared", Type: C.Direct}), closeErr: failure}
	proxy := adapter.NewProxy(a)
	tunnel.UpdateProxies(map[string]C.Proxy{"one": proxy, "two": adapter.NewProxy(a)}, nil)
	for i := 0; i < 2; i++ {
		if err := ApplyConfigContext(context.Background(), next, false); !errors.Is(err, failure) {
			t.Fatalf("close failure lost: %v", err)
		}
	}
	if a.calls.Load() != 1 || tunnel.Proxies()["one"] != proxy {
		t.Fatal("close repeated or old ownership discarded")
	}
}

func TestConfigRetirementClosesEveryDistinctAdapterExactlyOnce(t *testing.T) {
	_ = retirementFixture(t)
	// With one P, queued close goroutines begin after the launch loop. This
	// exercises the old range-variable semantics selected by go.mod (Go 1.20).
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	proxies := make(map[string]C.Proxy)
	var adapters []*retirementAdapter
	for _, name := range []string{"first", "second", "third", "fourth"} {
		a := &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Direct})}
		adapters = append(adapters, a)
		proxies[name] = adapter.NewProxy(a)
	}
	tunnel.UpdateProxies(proxies, nil)
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range adapters {
		if got := a.calls.Load(); got != 1 {
			t.Fatalf("adapter %s closed %d times", a.Name(), got)
		}
	}
}

func TestRetireConfigRestoresBootstrapOnlyAfterSuccessfulJoin(t *testing.T) {
	_ = retirementFixture(t)
	p := &retirementProvider{name: "slow", done: make(chan struct{})}
	tunnel.UpdateProxies(nil, map[string]P.ProxyProvider{"old": p})
	inner.New(tunnel.Tunnel)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := RetireConfig(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || inner.GetTunnel() == nil {
		t.Fatalf("premature bootstrap: %v", err)
	}
	close(p.done)
	if err := RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inner.GetTunnel() != nil || len(tunnel.Providers()) != 0 || len(tunnel.Proxies()) != 0 {
		t.Fatal("retired configuration remains usable")
	}
	if err := CancelConfigTasks(&config.Config{Providers: map[string]P.ProxyProvider{"again": p}}); err == nil {
		t.Fatal("retired provider was reusable")
	}
}

func TestConfigPublicationWaitsForRealRuleProviderNotification(t *testing.T) {
	next := retirementFixture(t)
	RP.SetTunnel(tunnel.Tunnel)
	p := RP.NewRuleSetProvider("rules", P.Domain, P.YamlRule, 0, resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules.yaml")), nil, nil, nil).(*RP.RuleSetProvider)
	entered, release := make(chan struct{}), make(chan struct{})
	subscription := tunnel.Tunnel.RuleUpdateCallback().Register(func(owner P.RuleProvider) {
		if owner == p {
			close(entered)
			<-release
		}
	})
	defer subscription.Close()
	tunnel.UpdateProxies(nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"rules": p})
	if _, _, err := p.SideUpdate([]byte("payload:\n  - example.com\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("real rule update not observed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := ApplyConfigContext(ctx, next, false)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || tunnel.RuleProviders()["rules"] != p {
		t.Fatalf("published before notification completed: %v", err)
	}
	close(release)
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if tunnel.RuleProviders()["rules"] == p {
		t.Fatal("retired rules still published")
	}
}

type refreshAtCancelProvider struct {
	*AP.ProxySetProvider
	once         sync.Once
	beforeCancel func()
}

func (p *refreshAtCancelProvider) Cancel() {
	p.once.Do(p.beforeCancel)
	p.ProxySetProvider.Cancel()
}

type finalRefreshAdapter struct {
	*retirementAdapter
	started, cancelled, release chan struct{}
}

func (a *finalRefreshAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	close(a.started)
	<-ctx.Done()
	close(a.cancelled)
	<-a.release
	return nil, ctx.Err()
}

func TestDirectConfigApplyJoinsURLTestPublishedDuringProviderCancellation(t *testing.T) {
	next := retirementFixture(t)
	old := adapter.NewProxy(outbound.NewDirect())
	a := &finalRefreshAdapter{
		retirementAdapter: &retirementAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "last-refresh", Type: C.Direct})},
		started:           make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}),
	}
	current := adapter.NewProxy(a)
	var release sync.Once
	t.Cleanup(func() { current.CancelURLTests(); release.Do(func() { close(a.release) }) })
	actual, err := AP.NewProxySetProvider("race", 0, nil, func(data []byte) ([]C.Proxy, error) {
		if string(data) == "initial" {
			return []C.Proxy{old}, nil
		}
		return []C.Proxy{current}, nil
	}, resource.NewFileVehicle(filepath.Join(t.TempDir(), "nodes.yaml")), AP.NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = actual.SideUpdate([]byte("initial")); err != nil {
		t.Fatal(err)
	}
	allowRefresh := make(chan struct{})
	refreshResult := make(chan error, 1)
	testResult := make(chan error, 1)
	go func() {
		<-allowRefresh
		_, _, err := actual.SideUpdate([]byte("last"))
		refreshResult <- err
		if err != nil {
			return
		}
		_, err = current.URLTest(context.Background(), "http://example.invalid", nil)
		testResult <- err
	}()
	p := &refreshAtCancelProvider{ProxySetProvider: actual, beforeCancel: func() {
		close(allowRefresh)
		if err := <-refreshResult; err != nil {
			t.Fatalf("final refresh: %v", err)
		}
		select {
		case <-a.started:
		case <-time.After(time.Second):
			t.Fatal("manual URL test did not start")
		}
	}}
	tunnel.UpdateProxies(nil, map[string]P.ProxyProvider{"race": p})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = ApplyConfigContext(ctx, next, false)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("new map published before final node's test joined: %v", err)
	}
	select {
	case <-a.cancelled:
	default:
		t.Fatal("URL test on last refreshed node was not cancelled")
	}
	if a.calls.Load() != 0 || tunnel.Providers()["race"] != p {
		t.Fatal("pool closed or maps replaced while test was active")
	}
	release.Do(func() { close(a.release) })
	if err := <-testResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("URL test result: %v", err)
	}
	if err := ApplyConfigContext(context.Background(), next, false); err != nil {
		t.Fatal(err)
	}
	if a.calls.Load() != 1 || len(current.DelayHistory()) != 0 {
		t.Fatal("final node retirement or late result protection failed")
	}
}
