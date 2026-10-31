package ntp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
)

// OwnedService defers the ordinary NTP loop until the embedding configuration
// activates it. Exchange, retry count, clock offset and system-write behavior
// remain in Service; this wrapper only owns cancellation and real socket closes.
type OwnedService struct {
	service          *Service
	interval         time.Duration
	mu               sync.Mutex
	started, retired bool
	done             chan struct{}
	closeErr         error
	failed           []io.Closer
}

func NewOwnedService(server string, interval time.Duration, physical C.Dialer, writeToSystem bool) *OwnedService {
	o := &OwnedService{interval: interval, done: make(chan struct{})}
	o.service = &Service{server: M.ParseSocksaddr(server), syncSystemTime: writeToSystem}
	o.service.dialer = ownedNTPDialer{SingDialer: proxydialer.NewSingDialer(physical), owner: o}
	return o
}

func (o *OwnedService) Activate(root context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired || root.Err() != nil {
		return context.Canceled
	}
	if o.started {
		return nil
	}
	// Validate the actual ticker duration before starting ownership. Overflow
	// must not panic after marking a service started without creating its worker.
	if o.interval <= 0 || o.interval > time.Duration(1<<63-1)/time.Minute {
		return errors.New("NTP interval cannot be represented as a ticker duration")
	}
	o.started = true
	o.service.ctx, o.service.cancel = context.WithCancel(root)
	o.service.ticker = time.NewTicker(o.interval * time.Minute)
	log.Infoln("NTP service start, sync system time is %t", o.service.syncSystemTime)
	go func() { defer close(o.done); o.service.loopUpdate() }()
	return nil
}

func (o *OwnedService) Cancel() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired {
		return
	}
	o.retired = true
	if o.started {
		o.service.Stop()
	} else {
		close(o.done)
	}
}

func (o *OwnedService) Wait(ctx context.Context) error {
	select {
	case <-o.done:
	default:
		select {
		case <-o.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeErr
}

type ownedNTPDialer struct {
	proxydialer.SingDialer
	owner *OwnedService
}

func (d ownedNTPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.SingDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	owned := &ownedNTPConn{Conn: conn, owner: d.owner}
	owned.mu.Lock()
	owned.stop = context.AfterFunc(ctx, func() { _ = owned.Close() })
	owned.mu.Unlock()
	return owned, nil
}

type ownedNTPConn struct {
	net.Conn
	owner *OwnedService
	mu    sync.Mutex
	stop  func() bool
	once  sync.Once
	err   error
}

func (c *ownedNTPConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		stop := c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		c.err = c.Conn.Close()
		if c.err != nil {
			c.owner.mu.Lock()
			c.owner.failed = append(c.owner.failed, c.Conn)
			c.owner.closeErr = errors.Join(c.owner.closeErr, c.err)
			c.owner.mu.Unlock()
		}
	})
	return c.err
}
