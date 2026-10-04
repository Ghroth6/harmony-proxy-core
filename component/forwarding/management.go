package forwarding

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
)

// Management network epochs describe a platform path, not a configuration or
// forwarding run. Pausing the path never retires providers or their schedulers.
var management struct {
	sync.Mutex
	enabled bool
	current *run
	last    uint64
}

type managementKey struct{}

var ErrManagementNetworkPaused = errors.New("management network is transitioning")

func newManagementRun() *run {
	management.last++
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{networkID: management.last, ctx: ctx, cancel: cancel, active: true, done: make(chan struct{}), resources: make(map[*resource]struct{})}
	return r
}

// EnableManagementNetwork preserves bootstrap networking. Later transitions
// must cancel and wait before changing platform protection conditions.
func EnableManagementNetwork() {
	management.Lock()
	defer management.Unlock()
	if !management.enabled {
		management.enabled = true
		management.current = newManagementRun()
		dialer.SetNetworkLifecycle(&dialer.NetworkLifecycle{
			Acquire:       AcquireManagementNetwork,
			OwnConn:       OwnNetworkConn,
			OwnPacketConn: OwnNetworkPacketConn,
		})
	}
}

func managementRun() *run {
	management.Lock()
	defer management.Unlock()
	return management.current
}

func CancelManagementNetwork() {
	if r := managementRun(); r != nil {
		r.stop()
	}
}

func WaitManagementNetwork(ctx context.Context) error {
	r := managementRun()
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return errors.Join(r.errors...)
	case <-ctx.Done():
		return fmt.Errorf("management network cleanup incomplete: %w", ctx.Err())
	}
}

// ResumeManagementNetwork cannot erase an unfinished or failed network epoch.
// Platform owner validation belongs to the application invoking this operation.
func ResumeManagementNetwork() error {
	management.Lock()
	defer management.Unlock()
	if !management.enabled {
		return nil
	}
	r := management.current
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped {
		return nil
	}
	if r.pending != 0 || len(r.errors) != 0 {
		return errors.Join(ErrManagementNetworkPaused, errors.Join(r.errors...))
	}
	management.current = newManagementRun()
	return nil
}

func managementOwner(ctx context.Context) *run {
	r, _ := ctx.Value(managementKey{}).(*run)
	return r
}

// SharedManagementNetworkContext snapshots the path for shared DNS work while
// removing any one waiter's cancellation and forwarding ownership. The shared
// worker must AcquireManagementNetwork before starting; delayed workers remain
// tied to this path even after Resume has installed a replacement.
func SharedManagementNetworkContext(parent context.Context) context.Context {
	r := managementOwner(parent)
	if r == nil {
		r = managementRun()
	}
	ctx := context.WithValue(context.WithoutCancel(parent), contextKey{}, (*run)(nil))
	return context.WithValue(ctx, managementKey{}, r)
}

// ManagementNetworkGeneration separates shared work queued on different paths.
// It is not a forwarding run ID and must not be used for traffic accounting.
func ManagementNetworkGeneration(ctx context.Context) uint64 {
	if r := managementOwner(ctx); r != nil {
		return r.networkID
	}
	return 0
}

// AcquireManagementNetwork binds an entire attempt, including result commit
// and callbacks, to its original path. Nested calls never adopt a newer epoch.
// finish cancels this attempt; pooled physical transports use their own socket
// registration instead of retaining this request's lifetime.
func AcquireManagementNetwork(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	r := managementOwner(parent)
	if r == nil {
		r = managementRun()
	}
	if r == nil {
		return parent, func() {}, nil
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return nil, nil, ErrManagementNetworkPaused
	}
	r.pending++
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(r.ctx, cancel)
	if r.ctx.Err() != nil {
		cancel()
	}
	ctx = context.WithValue(ctx, managementKey{}, r)
	if owner(ctx) == nil {
		ctx = context.WithValue(ctx, contextKey{}, r)
	}
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stop()
			cancel()
			r.mu.Lock()
			r.pending--
			r.checkDoneLocked()
			r.mu.Unlock()
		})
	}, nil
}

// CommitManagementNetwork serializes short publications against path changes.
// The action must not reenter network lifecycle operations or perform I/O waits.
func CommitManagementNetwork(ctx context.Context, action func() error) error {
	r := managementOwner(ctx)
	if r == nil {
		return action()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrManagementNetworkPaused
	}
	return action()
}

// OwnNetworkConn retains the physical path even for configuration-owned pools
// whose logical streams belong to different forwarding or management callers.
func OwnNetworkConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	r := managementOwner(ctx)
	if r == nil {
		return conn, nil
	}
	if udp, ok := conn.(*net.UDPConn); ok {
		c, err := own(context.WithValue(ctx, contextKey{}, r), conn)
		if err != nil {
			return nil, err
		}
		return &networkUDPConn{udp, c}, nil
	}
	return OwnConn(context.WithValue(ctx, contextKey{}, r), conn)
}

type networkPacketConn struct {
	net.PacketConn
	owned *resource
}

func (c *networkPacketConn) Close() error  { return c.owned.Close() }
func (c *networkPacketConn) Upstream() any { return c.PacketConn }

type networkUDPConn struct {
	*net.UDPConn
	owned *resource
}

func (c *networkUDPConn) Close() error  { return c.owned.Close() }
func (c *networkUDPConn) Upstream() any { return c.UDPConn }

func OwnNetworkPacketConn(ctx context.Context, conn net.PacketConn) (net.PacketConn, error) {
	r := managementOwner(ctx)
	if r == nil {
		return conn, nil
	}
	c, err := own(context.WithValue(ctx, contextKey{}, r), conn)
	if err != nil {
		return nil, err
	}
	if udp, ok := conn.(*net.UDPConn); ok {
		return &networkUDPConn{udp, c}, nil
	}
	return &networkPacketConn{conn, c}, nil
}
