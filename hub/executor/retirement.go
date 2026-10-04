package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/tunnel"
)

type configTaskOwner interface {
	Cancel()
	Wait(context.Context) error
}

type proxyTestOwner interface {
	CancelURLTests()
	WaitURLTests(context.Context) error
}

// A close is issued exactly once. A timeout retains the actual in-flight call;
// an opaque Close error cannot be cleared by calling Close a second time.
type configClose struct {
	once sync.Once
	done chan struct{}
	err  error
}

func (c *configClose) wait(ctx context.Context, closeFn func() error) error {
	c.once.Do(func() { go func() { c.err = closeFn(); close(c.done) }() })
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type configRetirement struct {
	providers map[P.Provider]struct{}
	proxies   map[C.Proxy]struct{}
	legacy    map[P.Provider]*configClose
	adapters  map[C.ProxyAdapter]*configClose
}

// Guarded by mux. Keep the old ownership until both retirement and publication
// succeed; a failed attempt is neither a rollback nor permission to restart it.
var retiringConfig *configRetirement

func providerSet(cfg *config.Config) map[P.Provider]struct{} {
	set := make(map[P.Provider]struct{})
	if cfg != nil {
		for _, p := range cfg.Providers {
			set[p] = struct{}{}
		}
		for _, p := range cfg.RuleProviders {
			set[p] = struct{}{}
		}
	}
	return set
}

// CancelConfigTasks closes admission for every non-reused old provider before
// any owner is waited on. Embedders can use it before joining their own calls
// into providers. It does not close proxy pools or publish a configuration.
func CancelConfigTasks(next *config.Config) error {
	mux.Lock()
	defer mux.Unlock()
	return cancelConfigTasksLocked(next)
}

func cancelConfigTasksLocked(next *config.Config) error {
	keep := providerSet(next)
	if retiringConfig == nil {
		retiringConfig = &configRetirement{
			providers: make(map[P.Provider]struct{}), legacy: make(map[P.Provider]*configClose),
			proxies:  make(map[C.Proxy]struct{}),
			adapters: make(map[C.ProxyAdapter]*configClose),
		}
	}
	for p := range retiringConfig.providers {
		if _, reused := keep[p]; reused {
			return fmt.Errorf("configuration reuses retired provider %q", p.Name())
		}
	}
	// Refuse new internal traffic before any old adapter is cancelled/closed.
	// A parse-time download must not route through a retired proxy map.
	tunnel.OnSuspend()
	keepProxies := make(map[C.Proxy]struct{})
	if next != nil {
		keepProxies = proxyObjects(next.Proxies, next.Providers)
	}
	for p := range retiringConfig.proxies {
		if _, reused := keepProxies[p]; reused {
			return fmt.Errorf("configuration reuses retired proxy tests %q", p.Name())
		}
	}
	for p := range proxyObjects(tunnel.Proxies(), tunnel.Providers()) {
		if _, reused := keepProxies[p]; reused {
			continue
		}
		if _, already := retiringConfig.proxies[p]; already {
			continue
		}
		retiringConfig.proxies[p] = struct{}{}
		if owner, ok := p.(proxyTestOwner); ok {
			owner.CancelURLTests()
		}
	}
	old := providerSet(&config.Config{Providers: tunnel.Providers(), RuleProviders: tunnel.RuleProviders()})
	for p := range old {
		if _, reused := keep[p]; reused {
			continue
		}
		if _, already := retiringConfig.providers[p]; already {
			continue
		}
		retiringConfig.providers[p] = struct{}{}
		if owner, ok := p.(configTaskOwner); ok {
			owner.Cancel()
		} else if _, ok := p.(io.Closer); ok {
			retiringConfig.legacy[p] = &configClose{done: make(chan struct{})}
		}
	}
	return nil
}

func proxyAdapters(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) map[C.ProxyAdapter]struct{} {
	adapters := make(map[C.ProxyAdapter]struct{})
	for p := range proxyObjects(proxies, providers) {
		adapters[p.Adapter()] = struct{}{}
	}
	return adapters
}

func proxyObjects(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) map[C.Proxy]struct{} {
	objects := make(map[C.Proxy]struct{})
	var visit func(C.Proxy)
	visit = func(p C.Proxy) {
		if p == nil {
			return
		}
		if _, seen := objects[p]; seen {
			return
		}
		objects[p] = struct{}{}
		a := p.Adapter()
		// Groups borrow their members; close each actual adapter once, without
		// touching selectors or limiting the walk to the selected member.
		if group, ok := a.(interface{ GetProxies(bool) []C.Proxy }); ok {
			for _, member := range group.GetProxies(false) {
				visit(member)
			}
		}
		if group, ok := a.(interface{ EmptyFallback() C.Proxy }); ok {
			visit(group.EmptyFallback())
		}
	}
	for _, p := range proxies {
		visit(p)
	}
	for _, provider := range providers {
		for _, p := range provider.Proxies() {
			visit(p)
		}
	}
	return objects
}

func retireConfigLocked(ctx context.Context, next *config.Config) error {
	if err := cancelConfigTasksLocked(next); err != nil {
		return err
	}
	var errs []error
	for p := range retiringConfig.proxies {
		if owner, ok := p.(proxyTestOwner); ok {
			if err := owner.WaitURLTests(ctx); err != nil {
				errs = append(errs, fmt.Errorf("retire proxy tests %q: %w", p.Name(), err))
			}
		}
	}
	for p := range retiringConfig.providers {
		var err error
		if owner, ok := p.(configTaskOwner); ok {
			err = owner.Wait(ctx)
		} else if call, ok := retiringConfig.legacy[p]; ok {
			err = call.wait(ctx, p.(io.Closer).Close)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("retire provider %q: %w", p.Name(), err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	old := proxyAdapters(tunnel.Proxies(), tunnel.Providers())
	keep := make(map[C.ProxyAdapter]struct{})
	if next != nil {
		keep = proxyAdapters(next.Proxies, next.Providers)
	}
	for a := range retiringConfig.adapters {
		if _, reused := keep[a]; reused {
			return fmt.Errorf("configuration reuses retired proxy %q", a.Name())
		}
	}
	for a := range old {
		if _, reused := keep[a]; reused {
			continue
		}
		if _, exists := retiringConfig.adapters[a]; !exists {
			retiringConfig.adapters[a] = &configClose{done: make(chan struct{})}
		}
	}
	// Start every close before waiting, so a slow dependency does not prevent
	// cancellation/cleanup of unrelated pools.
	for a, call := range retiringConfig.adapters {
		// This module targets Go 1.20: range variables are shared across
		// iterations even when tests/builds use a newer Go toolchain.
		a, call := a, call
		call.once.Do(func() { go func() { call.err = a.Close(); close(call.done) }() })
	}
	for a, call := range retiringConfig.adapters {
		if err := call.wait(ctx, a.Close); err != nil {
			errs = append(errs, fmt.Errorf("retire proxy %q: %w", a.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// RetireConfig joins all current configuration tasks and owned proxy pools.
// Failure preserves old maps for diagnosis; success clears the active maps and
// restores the internal bootstrap entry. Retired objects cannot be reused.
func RetireConfig(ctx context.Context) error {
	mux.Lock()
	defer mux.Unlock()
	if err := retireConfigLocked(ctx, nil); err != nil {
		return err
	}
	// There is now no usable configuration. Restore the ordinary bootstrap
	// state only after confirmed retirement; partial failure keeps ownership.
	inner.New(nil)
	tunnel.UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{})
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{})
	return nil
}
