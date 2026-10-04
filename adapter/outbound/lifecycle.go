package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// autoCloseProxyAdapter owns the protocol pool, admitted dials and connections.
// Retire drains existing leases after a provider removes the node. Close forces
// the same retirement during configuration shutdown. Neither requires GC.
type autoCloseProxyAdapter struct {
	ProxyAdapter
	lifetime *adapterLifetime
}

// Keep the owner containing the finalizer out of this graph. Returned wrappers
// hold that owner, but the lifetime only holds raw connection close records.
// Calling raw.AddRef(owner) here would create a cycle through the finalizer.
type adapterLifetime struct {
	mu            sync.Mutex
	adapter       ProxyAdapter
	leases        map[*adapterLease]struct{}
	failed        map[*adapterLease]struct{}
	retired       bool
	forced        bool
	closeStarted  bool
	closeFinished bool
	err           error
	done          chan struct{}
}

type adapterLease struct {
	lifetime *adapterLifetime
	cancel   context.CancelFunc
	closer   io.Closer // assigned under lifetime.mu, before close starts
	once     sync.Once
	err      error
}

func (s *adapterLifetime) acquire(ctx context.Context) (context.Context, *adapterLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return nil, nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	lease := &adapterLease{lifetime: s, cancel: cancel}
	s.leases[lease] = struct{}{}
	return ctx, lease, nil
}

// attach moves the dial lease to its returned connection without an unowned gap.
// A result arriving after force-close still belongs to this operation and must
// be closed before its lease is released.
func (l *adapterLease) attach(closer io.Closer) bool {
	s := l.lifetime
	s.mu.Lock()
	l.closer = closer
	forced := s.forced
	s.mu.Unlock()
	return forced
}

func (l *adapterLease) finish(err error) {
	l.cancel()
	s := l.lifetime
	s.mu.Lock()
	delete(s.leases, l)
	if err := adapterCloseError(err); err != nil {
		// A failed Close has returned, but the resource may still be live.
		// Preserve its owner without counting it as an unfinished call or
		// retrying an arbitrary protocol Close on subsequent waits.
		s.failed[l] = struct{}{}
		s.err = errors.Join(s.err, err)
	}
	s.advanceLocked()
	s.mu.Unlock()
}

func (l *adapterLease) close() error {
	l.once.Do(func() {
		l.err = l.closer.Close()
		l.finish(l.err)
	})
	return l.err
}

// Must hold mu. Starting Close in its own goroutine avoids running protocol
// cleanup on a stream Close stack that cleanup may itself wait for.
func (s *adapterLifetime) advanceLocked() {
	if !s.retired {
		return
	}
	if !s.closeStarted && (s.forced || len(s.leases) == 0) {
		s.closeStarted = true
		go func() {
			log.Debugln("Closing outdated proxy [%s]", s.adapter.Name())
			err := s.adapter.Close()
			s.mu.Lock()
			s.err = errors.Join(s.err, adapterCloseError(err))
			s.closeFinished = true
			s.advanceLocked()
			s.mu.Unlock()
		}()
	}
	if s.closeFinished && len(s.leases) == 0 {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
}

// Match forwarding/ingress retirement, also accepting smux's known closed
// stream result (as KcpTun does). An aggregate must retain unknown siblings.
func adapterCloseError(err error) error {
	if err == nil || err == net.ErrClosed || err == io.ErrClosedPipe {
		return nil
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var pending []error
		for _, child := range multi.Unwrap() {
			pending = append(pending, adapterCloseError(child))
		}
		return errors.Join(pending...)
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		if child := single.Unwrap(); child != nil && adapterCloseError(child) == nil {
			return nil
		}
	}
	return err
}

func (s *adapterLifetime) retire(force bool) {
	s.mu.Lock()
	s.retired = true
	if force && !s.forced {
		s.forced = true
		for lease := range s.leases {
			lease.cancel()
			if lease.closer != nil {
				lease := lease // this module retains Go 1.20 loop semantics
				go lease.close()
			}
		}
	}
	s.advanceLocked()
	s.mu.Unlock()
}

func (s *adapterLifetime) wait(ctx context.Context) error {
	select {
	case <-s.done:
	default:
		select {
		case <-s.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (p *autoCloseProxyAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	defer runtime.KeepAlive(p)
	ctx, lease, err := p.lifetime.acquire(ctx)
	if err != nil {
		return nil, err
	}
	c, err := p.ProxyAdapter.DialContext(ctx, metadata)
	if c == nil {
		lease.finish(nil)
		if err == nil {
			err = errors.New("proxy dial returned a nil connection")
		}
		return nil, err
	}
	forced := lease.attach(c)
	if err != nil || forced {
		if forced {
			err = errors.Join(err, net.ErrClosed)
		}
		return nil, errors.Join(err, lease.close())
	}
	return newLeasedConn(c, lease, p), nil
}

func (p *autoCloseProxyAdapter) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	defer runtime.KeepAlive(p)
	ctx, lease, err := p.lifetime.acquire(ctx)
	if err != nil {
		return nil, err
	}
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	if pc == nil {
		lease.finish(nil)
		if err == nil {
			err = errors.New("proxy listen returned a nil packet connection")
		}
		return nil, err
	}
	forced := lease.attach(pc)
	if err != nil || forced {
		if forced {
			err = errors.Join(err, net.ErrClosed)
		}
		return nil, errors.Join(err, lease.close())
	}
	return newLeasedPacketConn(pc, lease, p), nil
}

// Retire rejects new dials immediately, without interrupting already admitted
// dials or established connections. The last full connection Close starts pool
// cleanup. It is safe to call concurrently with Close and WaitRetired.
func (p *autoCloseProxyAdapter) Retire() {
	runtime.SetFinalizer(p, nil)
	p.lifetime.retire(false)
}

// WaitRetired waits for actual dial, connection and protocol Close completion.
// A timeout does not cancel or repeat cleanup; callers can wait again. Calling
// it before Retire/Close only waits and does not initiate retirement.
func (p *autoCloseProxyAdapter) WaitRetired(ctx context.Context) error {
	defer runtime.KeepAlive(p)
	return p.lifetime.wait(ctx)
}

// ForceRetire closes admission and starts all forced cleanup under the same
// lifetime as natural retirement. It does not wait; WaitRetired joins every
// registered dial and connection Close as well as the protocol Close result.
func (p *autoCloseProxyAdapter) ForceRetire() {
	runtime.SetFinalizer(p, nil)
	p.lifetime.retire(true)
}

// Close force-retires: cancel dials, close owned connections, and start protocol
// Close concurrently so it can unblock a dial that ignores cancellation. It
// returns only when all have returned; ForceRetire followed by WaitRetired
// offers a bounded wait for that same cleanup. Errors remain on later calls.
func (p *autoCloseProxyAdapter) Close() error {
	p.ForceRetire()
	return p.lifetime.wait(context.Background())
}

func NewAutoCloseProxyAdapter(adapter ProxyAdapter) ProxyAdapter {
	proxy := &autoCloseProxyAdapter{
		ProxyAdapter: adapter,
		lifetime: &adapterLifetime{
			adapter: adapter,
			leases:  make(map[*adapterLease]struct{}),
			failed:  make(map[*adapterLease]struct{}),
			done:    make(chan struct{}),
		},
	}
	// A fallback for abandoned adapters; provider/configuration owners retire
	// explicitly. Live returned wrappers preserve the previous AddRef behavior.
	runtime.SetFinalizer(proxy, (*autoCloseProxyAdapter).Close)
	return proxy
}
