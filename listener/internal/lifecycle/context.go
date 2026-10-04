package lifecycle

import (
	"context"

	C "github.com/metacubex/mihomo/constant"
)

// Context obtains the fixed owner from an embedded forwarding tunnel. Normal
// upstream listener construction has no forwarding owner and is unchanged.
func Context(tunnel C.Tunnel) context.Context {
	if scoped, ok := tunnel.(interface {
		BindContext(context.Context) context.Context
	}); ok {
		return scoped.BindContext(context.Background())
	}
	return context.Background()
}
