package protection

import (
	"context"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
)

type generationKey struct{}

// WithGeneration marks a mobile forwarding context. Its children retain the
// marker; zero and stale marked generations are rejected, never bypassed.
// The runtime must mark every forwarding root. Unmarked independent management
// retains its own routing policy; this function does not start a runtime.
func WithGeneration(parent context.Context, generation uint64) context.Context {
	return context.WithValue(parent, generationKey{}, generation)
}

// Generation reads the actual immutable socket-protection marker. Reading it
// does not register a gate, adopt a forwarding owner, or open a physical socket.
func Generation(ctx context.Context) uint64 {
	if ctx == nil {
		return 0
	}
	generation, _ := ctx.Value(generationKey{}).(uint64)
	return generation
}

// InstallDialerHook is called once at mobile process initialization. It never
// changes DefaultSocketHook or networking/bind policy, including on unregister.
func (g *Gate) InstallDialerHook() int32 {
	err := dialer.InstallOutboundSocketPolicy(dialer.OutboundSocketPolicy{
		Required: func(ctx context.Context) bool { _, marked := ctx.Value(generationKey{}).(uint64); return marked },
		Control: func(ctx context.Context, network, address string, conn syscall.RawConn) error {
			generation, _ := ctx.Value(generationKey{}).(uint64)
			return g.socketControl(generation, network, address, conn)
		},
	})
	if err != nil {
		return Busy
	}
	return Success
}
