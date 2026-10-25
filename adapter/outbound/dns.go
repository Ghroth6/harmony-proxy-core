package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

type Dns struct {
	*Base
	service func() resolver.Service
}

type DnsOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Dns) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	ctx, cancel, finish, service, err := d.relayContext(ctx)
	if err != nil {
		return nil, err
	}
	left, right := N.Pipe()
	conn := &dnsRelayConn{Conn: left, peer: right, cancel: cancel, done: make(chan struct{})}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callbackDone); _ = right.Close() })
	go func() {
		_ = resolver.RelayDnsProxyConn(ctx, right, 0, service)
		cancel()
		if !stop() {
			<-callbackDone
		}
		finish()
		close(conn.done)
	}()
	return NewConn(conn, d), nil
}

// A DNS proxy borrows one service and its owner for the whole association. A
// configured mobile getter never consults a later globally published service.
func (d *Dns) relayContext(ctx context.Context) (context.Context, context.CancelFunc, func(), resolver.Service, error) {
	var service resolver.Service
	if d.service != nil {
		service = d.service()
	} else {
		service = resolver.DefaultService
	}
	finish := func() {}
	if owner, ok := service.(interface {
		AcquireWorker(context.Context) (context.Context, func(), error)
	}); ok {
		var err error
		ctx, finish, err = owner.AcquireWorker(ctx)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if service != nil {
		service = dnsProxyService{service}
	}
	ctx, cancel := context.WithCancel(ctx)
	return ctx, cancel, finish, service, nil
}

type dnsProxyService struct{ resolver.Service }

func (s dnsProxyService) ServeMsg(ctx context.Context, request *D.Msg) (*D.Msg, error) {
	reply, err := s.Service.ServeMsg(ctx, request)
	// An owner can reject admission before its cancellation callback reaches
	// this association. Retirement must never become an ordinary SERVFAIL.
	if errors.Is(err, dns.ErrResolverRetired) || errors.Is(err, dns.ErrResolverNotActive) {
		err = errors.Join(context.Canceled, err)
	}
	return reply, err
}

type dnsRelayConn struct {
	net.Conn
	peer   net.Conn
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	err    error
}

func (c *dnsRelayConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.err = errors.Join(c.Conn.Close(), c.peer.Close())
		<-c.done
	})
	return c.err
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Dns) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	log.Debugln("[DNS] hijack udp:%s from %s", metadata.RemoteAddress(), metadata.SourceAddrPort())
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	ctx, cancel, finish, service, err := d.relayContext(ctx)
	if err != nil {
		return nil, err
	}
	conn := &dnsPacketConn{
		response: make(chan dnsPacket, 1),
		ctx:      ctx,
		cancel:   cancel,
		service:  service,
		done:     make(chan struct{}),
	}
	go func() {
		<-ctx.Done()
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		conn.workers.Wait()
		for {
			select {
			case packet := <-conn.response:
				packet.put()
			default:
				finish()
				close(conn.done)
				return
			}
		}
	}()
	return NewPacketConn(conn, d), nil
}

func (d *Dns) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() {
		metadata.DstIP = netip.AddrFrom4([4]byte{127, 0, 0, 2})
	}
	return nil
}

type dnsPacket struct {
	data []byte
	put  func()
	addr net.Addr
}

// dnsPacketConn implements net.PacketConn
type dnsPacketConn struct {
	response chan dnsPacket
	ctx      context.Context
	cancel   context.CancelFunc
	service  resolver.Service
	mu       sync.Mutex
	closed   bool
	workers  sync.WaitGroup
	done     chan struct{}
}

func (d *dnsPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	select {
	case packet := <-d.response:
		if d.ctx.Err() != nil {
			packet.put()
			return nil, nil, nil, net.ErrClosed
		}
		return packet.data, packet.put, packet.addr, nil
	case <-d.ctx.Done():
		return nil, nil, nil, net.ErrClosed
	}
}

func (d *dnsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-d.response:
		if d.ctx.Err() != nil {
			packet.put()
			return 0, nil, net.ErrClosed
		}
		n = copy(p, packet.data)
		if packet.put != nil {
			packet.put()
		}
		return n, packet.addr, nil
	case <-d.ctx.Done():
		return 0, nil, net.ErrClosed
	}
}

func (d *dnsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return 0, net.ErrClosed
	}
	d.workers.Add(1)
	d.mu.Unlock()

	if len(p) > resolver.SafeDnsPacketSize {
		// wtf???
		d.workers.Done()
		return len(p), nil
	}

	buf := pool.Get(resolver.SafeDnsPacketSize)
	put := func() { _ = pool.Put(buf) }
	copy(buf, p) // avoid p be changed after WriteTo returned

	go func() { // don't block the WriteTo function
		defer d.workers.Done()
		buf, err := resolver.RelayDnsProxyPacket(d.ctx, buf[:len(p)], buf, d.service)
		if err != nil {
			put()
			return
		}

		packet := dnsPacket{
			data: buf,
			put:  put,
			addr: addr,
		}
		select {
		case d.response <- packet:
			break
		case <-d.ctx.Done():
			put()
		}
	}()
	return len(p), nil
}

func (d *dnsPacketConn) Close() error {
	d.cancel()
	<-d.done
	return nil
}

func (*dnsPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 53,
		Zone: "",
	}
}

func (*dnsPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (*dnsPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (*dnsPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func NewDnsWithOption(option DnsOption) *Dns {
	return &Dns{
		service: option.DNSServiceForAPI,
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Dns,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
	}
}
