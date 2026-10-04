package provider

import (
	"context"
	"errors"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

// Native parser results own their adapters and expose graceful retirement.
// Custom parsers may instead return borrowed adapters; without this contract
// a refresh must not assume it may close a transport used by another owner.
type retiredAdapter interface {
	C.ProxyAdapter
	Retire()
	ForceRetire()
	WaitRetired(context.Context) error
}

type retiredTests interface {
	CancelURLTests()
	WaitURLTests(context.Context) error
}

type retiredProxy struct {
	adapter retiredAdapter
	tests   []retiredTests
	name    string
	done    chan struct{}
	err     error // guarded by provider mutex until done closes
}

// setProxies is called inside the Fetcher's commit fence. Only close admission
// here; neither a live stream nor a slow adapter Close may block publication.
func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.mutex.Lock()
	defer pp.mutex.Unlock()
	if pp.closed {
		return
	}
	keepAdapters := make(map[C.ProxyAdapter]struct{}, len(proxies))
	keepTests := make(map[C.Proxy]struct{}, len(proxies))
	for _, proxy := range proxies {
		keepAdapters[proxy.Adapter()] = struct{}{}
		keepTests[proxy] = struct{}{}
	}
	removed := make(map[C.ProxyAdapter]*retiredProxy)
	for _, proxy := range pp.proxies {
		if _, kept := keepTests[proxy]; kept {
			continue
		}
		adapter := proxy.Adapter()
		managed, owned := adapter.(retiredAdapter)
		if !owned {
			continue
		}
		entry := removed[adapter]
		if entry == nil {
			entry = &retiredProxy{name: proxy.Name(), done: make(chan struct{})}
			if _, reused := keepAdapters[adapter]; !reused {
				entry.adapter = managed
			}
			removed[adapter] = entry
		}
		if tests, ok := proxy.(retiredTests); ok {
			tests.CancelURLTests()
			entry.tests = append(entry.tests, tests)
		}
	}
	for _, entry := range removed {
		if entry.adapter == nil && len(entry.tests) == 0 {
			continue
		}
		if pp.retired == nil {
			pp.retired = make(map[*retiredProxy]struct{})
		}
		pp.retired[entry] = struct{}{}
		if entry.adapter != nil {
			entry.adapter.Retire()
		}
		go pp.finishRetiredProxy(entry)
	}
	pp.proxies = proxies
	pp.version++
	pp.healthCheck.setProxies(proxies)
	if pp.healthCheck.auto() {
		pp.healthCheck.checkAsync()
	}
}

func (pp *proxySetProvider) finishRetiredProxy(entry *retiredProxy) {
	var errs []error
	for _, tests := range entry.tests {
		errs = append(errs, tests.WaitURLTests(context.Background()))
	}
	if entry.adapter != nil {
		errs = append(errs, entry.adapter.WaitRetired(context.Background()))
	}
	err := errors.Join(errs...)
	pp.mutex.Lock()
	entry.err = err
	if err == nil {
		// Completed nodes leave no historical strong-reference collection.
		delete(pp.retired, entry)
	}
	pp.mutex.Unlock()
	if err != nil {
		// Further refreshes must not keep allocating after an unknown cleanup.
		// This runs outside both provider locks and the Fetcher commit fence.
		pp.Fetcher.Cancel()
	}
	close(entry.done)
}

func (pp *proxySetProvider) retiredProxies() []*retiredProxy {
	pp.mutex.RLock()
	defer pp.mutex.RUnlock()
	entries := make([]*retiredProxy, 0, len(pp.retired))
	for entry := range pp.retired {
		entries = append(entries, entry)
	}
	return entries
}

func (pp *proxySetProvider) forceRetiredProxies() {
	for _, entry := range pp.retiredProxies() {
		if entry.adapter != nil {
			entry.adapter.ForceRetire()
		}
	}
}

func (pp *proxySetProvider) waitRetiredProxies(ctx context.Context) error {
	var errs []error
	for _, entry := range pp.retiredProxies() {
		select {
		case <-entry.done:
		default:
			select {
			case <-entry.done:
			case <-ctx.Done():
				errs = append(errs, fmt.Errorf("retire previous proxy %q: %w", entry.name, ctx.Err()))
				continue
			}
		}
		if entry.err != nil {
			errs = append(errs, fmt.Errorf("retire previous proxy %q: %w", entry.name, entry.err))
		}
	}
	return errors.Join(errs...)
}

func (pp *proxySetProvider) retirementError() error {
	pp.mutex.RLock()
	defer pp.mutex.RUnlock()
	var errs []error
	for entry := range pp.retired {
		if entry.err != nil {
			errs = append(errs, fmt.Errorf("retire previous proxy %q: %w", entry.name, entry.err))
		}
	}
	return errors.Join(errs...)
}
