package dns

import (
	"context"
	"errors"
	"fmt"
	"github.com/metacubex/mihomo/component/resolver"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/deque"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

const maxOldDotConns = 8

type dnsOverTLS struct {
	port           string
	host           string
	dialer         *dnsDialer
	skipCertVerify bool
	nameCertVerify string
	disableReuse   bool

	access      sync.Mutex
	connections deque.Deque[net.Conn] // LIFO
}

var _ dnsClient = (*dnsOverTLS)(nil)

// Address implements dnsClient
func (t *dnsOverTLS) Address() string {
	return fmt.Sprintf("tls://%s", net.JoinHostPort(t.host, t.port))
}

func (t *dnsOverTLS) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if owner := resolverOwner(ctx); owner != nil {
		return t.exchangeOwned(ctx, m, owner)
	}
	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)

	go func() {
		var msg *D.Msg
		var err error
		defer func() { ch <- result{msg, err} }()
		for { // retry loop; only retry when reusing old conn
			err = ctx.Err() // check context first
			if err != nil {
				return
			}

			var conn net.Conn
			isOldConn := true

			if !t.disableReuse {
				t.access.Lock()
				if t.connections.Len() > 0 {
					conn = t.connections.PopBack()
				}
				t.access.Unlock()
			}

			if conn == nil {
				conn, err = t.dialContext(ctx)
				if err != nil {
					return
				}
				isOldConn = false
			}

			dClient := &D.Client{
				UDPSize: 4096,
				Timeout: 5 * time.Second,
			}
			dConn := &D.Conn{
				Conn:    conn,
				UDPSize: dClient.UDPSize,
			}

			msg, _, err = dClient.ExchangeWithConn(m, dConn)
			if err != nil {
				_ = conn.Close()
				conn = nil
				if isOldConn { // retry
					continue
				}
				return
			}

			if !t.disableReuse {
				t.access.Lock()
				if t.connections.Len() >= maxOldDotConns {
					oldConn := t.connections.PopFront()
					go oldConn.Close() // close in a new goroutine, not blocking the current task
				}
				t.connections.PushBack(conn)
				t.access.Unlock()
			} else {
				_ = conn.Close()
			}
			return
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

// The candidate owns the actual TLS read, not just an asynchronous waiter.
// Pooled sockets remain registered with that same owner until real Close.
func (t *dnsOverTLS) exchangeOwned(ctx context.Context, m *D.Msg, owner *ResolverOwner) (*D.Msg, error) {
	ctx, finish, err := owner.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var conn net.Conn
		if !t.disableReuse {
			t.access.Lock()
			if t.connections.Len() > 0 {
				conn = t.connections.PopBack()
			}
			t.access.Unlock()
		}
		isOld := conn != nil
		if conn == nil {
			conn, err = t.dialContext(ctx)
			if err != nil {
				return nil, err
			}
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(closed); _ = conn.Close() })
		client := &D.Client{UDPSize: 4096, Timeout: 5 * time.Second}
		msg, _, exchangeErr := client.ExchangeWithConn(m, &D.Conn{Conn: conn, UDPSize: client.UDPSize})
		if !stop() {
			<-closed
		}
		if ctx.Err() != nil {
			exchangeErr = ctx.Err()
		}
		if exchangeErr != nil {
			_ = conn.Close()
			if isOld && ctx.Err() == nil {
				continue
			}
			return nil, exchangeErr
		}
		if t.disableReuse {
			if err = conn.Close(); err != nil {
				return nil, err
			}
			return msg, nil
		}
		var evicted net.Conn
		err = owner.commit(func() error {
			t.access.Lock()
			defer t.access.Unlock()
			if t.connections.Len() >= maxOldDotConns {
				evicted = t.connections.PopFront()
			}
			t.connections.PushBack(conn)
			return nil
		})
		if evicted != nil {
			_ = evicted.Close() // this worker remains owned until Close returns.
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return msg, nil
	}
}

func (t *dnsOverTLS) dialContext(ctx context.Context) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.host, t.port))
	if err != nil {
		return nil, err
	}
	if owner := resolverOwner(ctx); owner != nil {
		conn, err = owner.ownConn(conn)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         t.host,
			InsecureSkipVerify: t.skipCertVerify,
		},
		NameCertVerify: t.nameCertVerify,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if raw, ok := conn.(*resolverConn); ok {
		return &resolverTLSConn{Conn: tlsConn, raw: raw}, nil
	}
	conn = tlsConn

	return conn, nil
}

// TLS may report a failed closeNotify after retirement denies new writes even
// though its actual socket Close succeeded. Only that verified result is
// benign; physical Close failures remain attached to the owner.
type resolverTLSConn struct {
	*tls.Conn
	raw  *resolverConn
	once sync.Once
	err  error
}

func (c *resolverTLSConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		if errors.Is(c.err, ErrResolverRetired) && c.raw.Close() == nil {
			c.err = nil
		}
	})
	return c.err
}

func (t *dnsOverTLS) ResetConnection() {
	if !t.disableReuse {
		t.access.Lock()
		for t.connections.Len() > 0 {
			oldConn := t.connections.PopFront()
			go oldConn.Close() // close in a new goroutine, not blocking the current task
		}
		t.access.Unlock()
	}
}

func (t *dnsOverTLS) Close() error {
	runtime.SetFinalizer(t, nil)
	t.access.Lock()
	var connections []net.Conn
	for t.connections.Len() > 0 {
		connections = append(connections, t.connections.PopFront())
	}
	t.access.Unlock()
	var errs []error
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func newDoTClient(addr string, resolver resolver.Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverTLS {
	host, port, _ := net.SplitHostPort(addr)
	c := &dnsOverTLS{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
	}
	c.connections.SetBaseCap(maxOldDotConns)
	if params["skip-cert-verify"] == "true" {
		c.skipCertVerify = true
	}
	c.nameCertVerify = params["name-cert-verify"]
	if params["disable-reuse"] == "true" {
		c.disableReuse = true
	}
	runtime.SetFinalizer(c, (*dnsOverTLS).Close)
	return c
}
