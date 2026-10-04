package outboundgroup

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// IdentitySelectAble preserves the source of an explicit selection across
// provider refreshes. A nil provider denotes a static proxy object. Automatic
// groups retain their existing health/fallback policy; SelectedProxy reports
// the actual current choice, which need not be the preferred identity.
type IdentitySelectAble interface {
	SetIdentity(C.Proxy, P.ProxyProvider) error
	SelectedProxy() C.Proxy
}

type proxySelection struct {
	name      string
	proxy     C.Proxy
	provider  P.ProxyProvider
	qualified bool
}

type selectionState struct{ atomic.Pointer[proxySelection] }

var ErrSelectionUnavailable = errors.New("selected proxy identity is unavailable")

type unavailableSelection struct{ *outbound.Base }

func (*unavailableSelection) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return nil, ErrSelectionUnavailable
}
func (*unavailableSelection) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, ErrSelectionUnavailable
}

var unavailableProxy = adapter.NewProxy(&unavailableSelection{outbound.NewBase(outbound.BaseOption{
	Name: "(selection unavailable)", Type: C.Reject,
})})

func (gb *GroupBase) selectedName() string {
	if selected := gb.selection.Load(); selected != nil {
		return selected.name
	}
	return ""
}

func (gb *GroupBase) setLegacySelection(name string) {
	if name == "" {
		gb.selection.Store(nil)
	} else {
		gb.selection.Store(&proxySelection{name: name})
	}
}

// Validation and publication need not lock a provider. The immutable binding
// never becomes a bare name: a concurrent refresh can make it unavailable, but
// cannot redirect it to a different provider. An in-flight dial may use the
// object from the snapshot it already resolved, as with ordinary provider I/O.
func (gb *GroupBase) setIdentity(proxy C.Proxy, provider P.ProxyProvider) error {
	if proxy == nil {
		return errors.New("selected proxy is nil")
	}
	selected := &proxySelection{name: proxy.Name(), proxy: proxy, provider: provider, qualified: true}
	members := gb.GetProxies(false)
	count, present := 0, false
	for _, member := range members {
		if member.Name() == selected.name {
			count++
		}
		present = present || member == proxy
	}
	if !present {
		return errors.New("selected proxy is not a current member")
	}
	if count != 1 {
		return errors.New("group has ambiguous members with the selected name")
	}
	if provider != nil {
		belongs := false
		for _, member := range gb.providers {
			belongs = belongs || member == provider
		}
		if !belongs || selected.resolve(members) != proxy {
			return errors.New("selected proxy does not belong to the current provider")
		}
	}
	gb.selection.Store(selected)
	return nil
}

func (selected *proxySelection) resolve(members []C.Proxy) C.Proxy {
	if selected == nil {
		return nil
	}
	if !selected.qualified {
		for _, member := range members {
			if member.Name() == selected.name {
				return member
			}
		}
		return nil
	}
	target := selected.proxy
	if selected.provider != nil {
		target = nil
		for _, current := range selected.provider.Proxies() {
			if current.Name() == selected.name {
				if target != nil && target != current {
					return nil // A provider itself must not have ambiguous identities.
				}
				target = current
			}
		}
	}
	for _, member := range members {
		if member == target {
			return member // Honor the group's current filters as well as its source.
		}
	}
	return nil
}
