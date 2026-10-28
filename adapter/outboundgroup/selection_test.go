package outboundgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Only health outcomes are synthetic. Membership, refresh, filtering and
// selection below use the production provider and group implementations.
type selectionTestProxy struct {
	C.Proxy
	alive atomic.Bool
	tests atomic.Int32
}

func selectionProxy(name string, alive bool) *selectionTestProxy {
	p := &selectionTestProxy{Proxy: adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name}))}
	p.alive.Store(alive)
	return p
}
func (p *selectionTestProxy) AliveForTestUrl(string) bool { return p.alive.Load() }
func (p *selectionTestProxy) LastDelayForTestUrl(string) uint16 {
	if p.alive.Load() {
		return 1
	}
	return 65535
}
func (p *selectionTestProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
	if p.alive.Load() {
		return 1, nil
	}
	return 0, errors.New("synthetic unhealthy node")
}

func selectionProvider(t *testing.T, name string, versions map[string][]C.Proxy) (*provider.ProxySetProvider, func(string)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".txt")
	if err := os.WriteFile(path, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	hc := provider.NewHealthCheck(nil, "", 1000, 0, true, nil)
	p, err := provider.NewProxySetProvider(name, 0, nil, func(data []byte) ([]C.Proxy, error) {
		return versions[string(data)], nil
	}, resource.NewFileVehicle(path), hc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if err := p.Initial(); err != nil {
		t.Fatal(err)
	}
	return p, func(version string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(version), 0600); err != nil {
			t.Fatal(err)
		}
		if err := p.Update(); err != nil {
			t.Fatal(err)
		}
	}
}

type selectionGroup interface {
	ProxyGroup
	SelectAble
}

func selectionTestGroup(t *testing.T, kind string, options GroupCommonOption, providers ...P.ProxyProvider) selectionGroup {
	t.Helper()
	options.Name = "choice"
	options.URL = "https://synthetic.invalid/"
	fallback := selectionProxy("empty", true)
	var group selectionGroup
	var err error
	switch kind {
	case "selector":
		group, err = NewSelector(options, SelectorOption{}, fallback, providers)
	case "urltest":
		group, err = NewURLTest(options, URLTestOption{}, fallback, providers)
	case "fallback":
		group, err = NewFallback(options, FallbackOption{}, fallback, providers)
	}
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestNameSelectionUsesUpstreamFallbackAfterRemoval(t *testing.T) {
	first, chosen := selectionProxy("first", true), selectionProxy("chosen", true)
	pd, refresh := selectionProvider(t, "P", map[string][]C.Proxy{"initial": {first, chosen}, "removed": {first}})
	group := selectionTestGroup(t, "selector", GroupCommonOption{}, pd)
	if err := group.Set("chosen"); err != nil {
		t.Fatal(err)
	}
	if group.Unwrap(nil, false) != chosen {
		t.Fatal("named selection not applied")
	}
	refresh("removed")
	if group.Unwrap(nil, false) != first {
		t.Fatal("missing name did not follow upstream first-member fallback")
	}
}
