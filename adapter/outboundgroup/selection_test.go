package outboundgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
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
	IdentitySelectAble
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

func TestIdentitySelectionSurvivesOtherProviderCollisionAndOwnRefresh(t *testing.T) {
	for _, kind := range []string{"selector", "urltest", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			aOld, aNew, bOld, bNew := selectionProxy("x", true), selectionProxy("x", true), selectionProxy("y", true), selectionProxy("x", true)
			a, refreshA := selectionProvider(t, "A", map[string][]C.Proxy{"initial": {aOld}, "new": {aNew}, "gone": {selectionProxy("z", true)}})
			b, refreshB := selectionProvider(t, "B", map[string][]C.Proxy{"initial": {bOld}, "collision": {bNew}})
			group := selectionTestGroup(t, kind, GroupCommonOption{}, b, a)
			if err := group.SetIdentity(aOld, a); err != nil {
				t.Fatal(err)
			}
			refreshB("collision")
			if group.SelectedProxy() != aOld {
				t.Fatal("another provider captured the selected identity")
			}
			refreshA("new")
			if group.SelectedProxy() != aNew {
				t.Fatal("same provider refresh lost the selected identity")
			}
			refreshA("gone")
			if kind == "selector" {
				if group.SelectedProxy() != unavailableProxy {
					t.Fatal("missing selection silently fell back")
				}
				if _, err := group.DialContext(context.Background(), nil); !errors.Is(err, ErrSelectionUnavailable) {
					t.Fatalf("TCP did not fail closed: %v", err)
				}
				if _, err := group.ListenPacketContext(context.Background(), nil); !errors.Is(err, ErrSelectionUnavailable) {
					t.Fatalf("UDP did not fail closed: %v", err)
				}
			} else if got := group.SelectedProxy(); got == aOld || got == aNew || got == unavailableProxy {
				t.Fatal("automatic group did not switch to a current member")
			}
			refreshA("new")
			if group.SelectedProxy() != aNew {
				t.Fatal("missing provider target lost preference before recovery")
			}
			group.ForceSet("")
			if kind != "urltest" && group.SelectedProxy() != bNew {
				t.Fatal("empty ForceSet did not restore default choice")
			}
			if kind == "urltest" && group.(*URLTest).selection.Load() != nil {
				t.Fatal("empty ForceSet retained URLTest identity preference")
			}
		})
	}
}

func TestURLTestDropsRemovedFastObjectWhenAnotherProviderHasSameName(t *testing.T) {
	aOld, aNew, bOld, bNew := selectionProxy("x", true), selectionProxy("z", true), selectionProxy("y", true), selectionProxy("x", true)
	a, refreshA := selectionProvider(t, "A", map[string][]C.Proxy{"initial": {aOld}, "gone": {aNew}})
	b, refreshB := selectionProvider(t, "B", map[string][]C.Proxy{"initial": {bOld}, "collision": {bNew}})
	group := selectionTestGroup(t, "urltest", GroupCommonOption{}, a, b)
	if err := group.SetIdentity(aOld, a); err != nil {
		t.Fatal(err)
	}
	if group.SelectedProxy() != aOld {
		t.Fatal("preferred identity did not seed the fast-node cache")
	}
	refreshB("collision")
	refreshA("gone")
	// The other same-name node must be after index zero: an old name-based
	// membership check would retain the removed A object through tolerance.
	if got := group.SelectedProxy(); got != aNew && got != bNew {
		t.Fatal("automatic strategy retained a removed same-name object")
	}
}

func TestIdentitySelectionKeepsAutomaticHealthPolicy(t *testing.T) {
	for _, kind := range []string{"urltest", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			target, healthy := selectionProxy("target", true), selectionProxy("healthy", true)
			p, _ := selectionProvider(t, "P", map[string][]C.Proxy{"initial": {healthy, target}})
			group := selectionTestGroup(t, kind, GroupCommonOption{}, p)
			if err := group.SetIdentity(target, p); err != nil {
				t.Fatal(err)
			}
			if group.SelectedProxy() != target {
				t.Fatal("healthy preferred identity not selected")
			}
			target.alive.Store(false)
			if group.SelectedProxy() != healthy {
				t.Fatal("dead preferred identity disabled automatic fallback")
			}
			if err := group.SetIdentity(target, p); err != nil {
				t.Fatal(err)
			}
			if kind == "fallback" && target.tests.Load() != 1 {
				t.Fatal("Fallback.SetIdentity skipped existing dead-node health check")
			}
			if group.SelectedProxy() != healthy {
				t.Fatal("failed health check prevented automatic fallback")
			}
			target.alive.Store(true)
			if kind == "urltest" && group.SelectedProxy() != target {
				t.Fatal("URLTest lost preference after recovery")
			}
			if kind == "fallback" && group.SelectedProxy() != healthy {
				t.Fatal("Fallback did not clear its confirmed unhealthy preference")
			}
		})
	}
}

func TestIdentitySelectionRejectsAmbiguityStaleObjectsAndFilteredMembers(t *testing.T) {
	old, replacement, rejected := selectionProxy("x", true), selectionProxy("x", true), adapter.NewProxy(outbound.NewRejectWithOption(outbound.RejectOption{Name: "x"}))
	a, refreshA := selectionProvider(t, "A", map[string][]C.Proxy{"initial": {old}, "new": {replacement}, "filtered": {rejected}})
	b, refreshB := selectionProvider(t, "B", map[string][]C.Proxy{"initial": {selectionProxy("y", true)}, "collision": {selectionProxy("x", true)}})
	group := selectionTestGroup(t, "selector", GroupCommonOption{ExcludeType: "Reject"}, b, a)
	if err := group.SetIdentity(old, b); err == nil {
		t.Fatal("accepted wrong provider provenance")
	}
	refreshA("new")
	if err := group.SetIdentity(old, a); err == nil {
		t.Fatal("accepted replaced object from stale catalog")
	}
	if err := group.SetIdentity(replacement, a); err != nil {
		t.Fatal(err)
	}
	refreshA("filtered")
	if group.SelectedProxy() != unavailableProxy {
		t.Fatal("refresh bypassed group filters")
	}
	refreshA("new")
	refreshB("collision")
	if err := group.SetIdentity(replacement, a); err == nil {
		t.Fatal("accepted initially ambiguous selection")
	}
	if group.SelectedProxy() != replacement {
		t.Fatal("rejected selection replaced earlier valid binding")
	}
}

func TestStaticIdentityAndLegacySelectionClearBindings(t *testing.T) {
	for _, kind := range []string{"selector", "urltest", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			static, other := selectionProxy("static", true), selectionProxy("other", true)
			hc := provider.NewHealthCheck(nil, "", 1000, 0, true, nil)
			p, err := provider.NewCompatibleProvider("static-source", []C.Proxy{other, static}, hc)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			group := selectionTestGroup(t, kind, GroupCommonOption{}, p)
			if err := group.SetIdentity(static, nil); err != nil {
				t.Fatal(err)
			}
			if group.SelectedProxy() != static {
				t.Fatal("static identity failed")
			}
			if err := group.Set("other"); err != nil {
				t.Fatal(err)
			}
			if group.SelectedProxy() != other {
				t.Fatal("legacy Set retained identity binding")
			}
			if err := group.SetIdentity(static, nil); err != nil {
				t.Fatal(err)
			}
			group.ForceSet("other")
			if group.SelectedProxy() != other {
				t.Fatal("legacy ForceSet retained identity binding")
			}
		})
	}
}

func TestConcurrentIdentityAndLegacySelection(t *testing.T) {
	first, second := selectionProxy("first", true), selectionProxy("second", true)
	p, _ := selectionProvider(t, "P", map[string][]C.Proxy{"initial": {first, second}})
	for _, kind := range []string{"selector", "urltest", "fallback"} {
		group := selectionTestGroup(t, kind, GroupCommonOption{}, p)
		var workers sync.WaitGroup
		for i := 0; i < 4; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for j := 0; j < 100; j++ {
					_ = group.SetIdentity(first, p)
					group.ForceSet("second")
					if got := group.SelectedProxy(); got != first && got != second {
						t.Error("invalid concurrent selection")
					}
				}
			}()
		}
		workers.Wait()
	}
}
