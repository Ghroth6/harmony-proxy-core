package adapter

import (
	"errors"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/lifecycle"
)

type resourceOwnedAdapter struct {
	outbound.ProxyAdapter
	resources *lifecycle.Group
	release   func()
}

func (a *resourceOwnedAdapter) ActivateResources() error { return a.resources.Activate() }

func (a *resourceOwnedAdapter) Close() error {
	err := errors.Join(a.ProxyAdapter.Close(), a.resources.Close())
	if err == nil {
		a.release()
	}
	return err
}
