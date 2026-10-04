// Package forwarding provides opt-in ownership for an embedded proxy's data
// plane. A background context is an explicit management request; a nil context
// at a root tunnel entry is admitted into the current forwarding generation.
package forwarding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

var ErrStopped = errors.New("forwarding is stopped")

type contextKey struct{}

type run struct {
	mu         sync.Mutex
	id         uint64
	networkID  uint64
	ctx        context.Context
	cancel     context.CancelFunc
	stopped    bool
	active     bool
	pending    int
	done       chan struct{}
	doneClosed bool
	resources  map[*resource]struct{}
	errors     []error
}

var lifecycle struct {
	sync.Mutex
	enabled bool
	current *run
	last    uint64
}

// Enable closes admission until Start is called. It is idempotent and does not
// change an existing generation. Without Enable, upstream admission is unchanged.
func Enable() { lifecycle.Lock(); lifecycle.enabled = true; lifecycle.Unlock() }

func Start(parent context.Context, generation uint64) error {
	if err := Prepare(parent, generation); err != nil {
		return err
	}
	return Activate(generation)
}

// Prepare records ownership before constructing any listener or platform TUN.
// Root admission remains closed until all constructors have succeeded.
func Prepare(parent context.Context, generation uint64) error {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if !lifecycle.enabled {
		return errors.New("forwarding lifecycle is not enabled")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	if generation == 0 || generation <= lifecycle.last {
		return errors.New("forwarding generation must increase")
	}
	if old := lifecycle.current; old != nil {
		old.mu.Lock()
		clean := old.stopped && old.pending == 0 && len(old.errors) == 0
		old.mu.Unlock()
		if !clean {
			return errors.New("previous forwarding generation has not finished cleanup")
		}
	}
	ctx, cancel := context.WithCancel(parent)
	r := &run{id: generation, cancel: cancel, done: make(chan struct{}), resources: make(map[*resource]struct{})}
	r.ctx = context.WithValue(ctx, contextKey{}, r)
	lifecycle.current, lifecycle.last = r, generation
	context.AfterFunc(ctx, r.stop)
	return nil
}

func Activate(generation uint64) error {
	r := current()
	if r == nil || r.id != generation {
		return ErrStopped
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.ctx.Err() != nil {
		return ErrStopped
	}
	r.active = true
	return nil
}

func Context(generation uint64) (context.Context, error) {
	r := current()
	if r == nil || r.id != generation {
		return nil, ErrStopped
	}
	return r.ctx, nil
}

// Bind preserves a caller's cancellation while fixing the owner to a particular
// listener generation. It is used once per internal connection, not per packet.
func Bind(parent, scope context.Context) context.Context {
	if Generation(parent) == Generation(scope) {
		return parent
	}
	if parent == nil || parent.Done() == nil {
		return scope
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(scope, cancel)
	context.AfterFunc(ctx, func() { stop() })
	return context.WithValue(ctx, contextKey{}, owner(scope))
}

func current() *run { lifecycle.Lock(); defer lifecycle.Unlock(); return lifecycle.current }

// Cancel prevents admission synchronously. Potentially blocking Close methods
// run separately; Stop waits for their real completion.
func Cancel() {
	if r := current(); r != nil {
		r.stop()
	}
}

func Stop(ctx context.Context) error {
	r := current()
	if r == nil {
		return nil
	}
	r.stop()
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return errors.Join(r.errors...)
	case <-ctx.Done():
		return fmt.Errorf("forwarding generation %d cleanup incomplete: %w", r.id, ctx.Err())
	}
}

func (r *run) stop() {
	r.mu.Lock()
	r.stopped = true
	r.cancel()
	resources := make([]*resource, 0, len(r.resources))
	for owned := range r.resources {
		resources = append(resources, owned)
	}
	r.checkDoneLocked()
	r.mu.Unlock()
	for _, owned := range resources {
		go owned.Close()
	}
}

func (r *run) checkDoneLocked() {
	if r.stopped && r.pending == 0 && !r.doneClosed {
		close(r.done)
		r.doneClosed = true
	}
}

func owner(ctx context.Context) *run {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(contextKey{}).(*run)
	return r
}

func Generation(ctx context.Context) uint64 {
	if r := owner(ctx); r != nil {
		return r.id
	}
	return 0
}

// Acquire is a completion lease, including work which ignores cancellation.
// Descendants inherit the original owner, never whichever run happens to be
// current when a delayed dial returns.
func Acquire(ctx context.Context) (context.Context, func(), error) {
	return acquire(ctx, false)
}

// AcquireConstruction holds the generation open while a listener constructor
// registers its resources. It permits a prepared run, never a stopped run;
// protocol request admission must continue to use Acquire.
func AcquireConstruction(ctx context.Context) (context.Context, func(), error) {
	return acquire(ctx, true)
}

func acquire(ctx context.Context, allowPrepared bool) (context.Context, func(), error) {
	if ctx == nil {
		lifecycle.Lock()
		if !lifecycle.enabled {
			lifecycle.Unlock()
			return context.Background(), func() {}, nil
		}
		r := lifecycle.current
		lifecycle.Unlock()
		if r == nil {
			return nil, nil, ErrStopped
		}
		ctx = r.ctx
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r := owner(ctx)
	if r == nil {
		return ctx, func() {}, nil
	}
	r.mu.Lock()
	if r.stopped || (!r.active && !allowPrepared) {
		r.mu.Unlock()
		return nil, nil, ErrStopped
	}
	r.pending++
	r.mu.Unlock()
	var once sync.Once
	return ctx, func() { once.Do(func() { r.mu.Lock(); r.pending--; r.checkDoneLocked(); r.mu.Unlock() }) }, nil
}

// Publish linearizes connection registration against cancellation. The callback
// must only store the record; user callbacks must run after Publish returns.
func Publish(ctx context.Context, store func()) bool {
	r := owner(ctx)
	if r == nil {
		if ctx != nil && ctx.Err() != nil {
			return false
		}
		store()
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || ctx.Err() != nil {
		return false
	}
	store()
	return true
}

type resource struct {
	r      *run
	closer io.Closer
	once   sync.Once
	err    error
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

// Cleanup retains a connection's accounting cleanup alongside its descriptor.
// Callers must hold an Acquire or AcquireConstruction lease while registering it.
func Cleanup(ctx context.Context, close func() error) func() error {
	if owner(ctx) == nil {
		return close
	}
	c := &resource{r: owner(ctx), closer: closeFunc(close)}
	c.r.mu.Lock()
	c.r.pending++
	c.r.resources[c] = struct{}{}
	stopped := c.r.stopped || ctx.Err() != nil
	c.r.mu.Unlock()
	if stopped {
		go c.Close()
	}
	return c.Close
}

func (c *resource) Close() error {
	c.once.Do(func() {
		c.err = c.closer.Close()
		if c.r != nil {
			c.r.mu.Lock()
			if err := closeError(c.err); err != nil {
				c.r.errors = append(c.r.errors, err)
				// Keep the failed object's ownership. Arbitrary protocol Close
				// methods are not guaranteed retryable; never erase an uncertain
				// descriptor and then admit a new generation.
			} else {
				delete(c.r.resources, c)
			}
			c.r.pending--
			c.r.checkDoneLocked()
			c.r.mu.Unlock()
		}
	})
	return c.err
}

func own(ctx context.Context, closer io.Closer) (*resource, error) {
	c := &resource{r: owner(ctx), closer: closer}
	if c.r != nil {
		c.r.mu.Lock()
		// Even a late result is retained until Close completes. Its originating
		// Acquire lease prevents Stop from claiming completion before this point.
		c.r.pending++
		c.r.resources[c] = struct{}{}
		stopped := c.r.stopped || ctx.Err() != nil
		c.r.mu.Unlock()
		if stopped {
			go c.Close()
			return nil, ErrStopped
		}
	} else if ctx != nil && ctx.Err() != nil {
		_ = c.Close()
		return nil, ctx.Err()
	}
	return c, nil
}

type netConn struct {
	net.Conn
	owned *resource
}

func (c *netConn) Upstream() any { return c.Conn }
func (c *netConn) Close() error  { return c.owned.Close() }

type tcpNetConn struct {
	*net.TCPConn
	owned *resource
}

func (c *tcpNetConn) Close() error  { return c.owned.Close() }
func (c *tcpNetConn) Upstream() any { return c.TCPConn }
func OwnConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if owner(ctx) == nil {
		return conn, nil
	}
	c, err := own(ctx, conn)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		return &tcpNetConn{tcp, c}, nil
	}
	return &netConn{conn, c}, nil
}

type tcpConn struct {
	C.Conn
	owned *resource
}

func (c *tcpConn) Upstream() any { return c.Conn }

func (c *tcpConn) Close() error { return c.owned.Close() }
func OwnTCP(ctx context.Context, conn C.Conn) (C.Conn, error) {
	if owner(ctx) == nil {
		if ctx.Err() != nil {
			_ = conn.Close()
			return nil, ctx.Err()
		}
		return conn, nil
	}
	c, err := own(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &tcpConn{conn, c}, nil
}

type udpConn struct {
	C.PacketConn
	owned *resource
}

func (c *udpConn) Upstream() any { return c.PacketConn }

func (c *udpConn) Close() error { return c.owned.Close() }
func OwnUDP(ctx context.Context, conn C.PacketConn) (C.PacketConn, error) {
	if owner(ctx) == nil {
		if ctx.Err() != nil {
			_ = conn.Close()
			return nil, ctx.Err()
		}
		return conn, nil
	}
	c, err := own(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &udpConn{conn, c}, nil
}
