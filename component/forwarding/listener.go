package forwarding

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"
)

type listenConfig struct {
	C.InboundListenConfig
	ctx context.Context
}

// WrapListenConfig is only for proxy listeners. Controller and DNS listeners
// deliberately keep their own lifetime contracts.
func WrapListenConfig(config C.InboundListenConfig) C.InboundListenConfig {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if !lifecycle.enabled {
		return config
	}
	var ctx context.Context
	if lifecycle.current != nil {
		ctx = lifecycle.current.ctx
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		cancel()
	}
	return &listenConfig{config, ctx}
}

func (c *listenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := c.InboundListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &listener{Listener: l, ctx: c.ctx}, nil
}

type listener struct {
	net.Listener
	ctx context.Context
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ctx, finish, err := Acquire(l.ctx)
		if err != nil {
			_ = conn.Close()
			continue
		}
		owned, err := OwnConn(ctx, conn)
		finish()
		if err != nil {
			continue
		}
		return owned, nil
	}
}

// WrapListener covers proxy constructors that call net.Listen directly.
func WrapListener(l net.Listener) net.Listener {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if !lifecycle.enabled {
		return l
	}
	if lifecycle.current == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return &listener{l, ctx}
	}
	return &listener{l, lifecycle.current.ctx}
}
