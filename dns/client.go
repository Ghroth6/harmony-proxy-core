package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type client struct {
	port   string
	host   string
	dialer *dnsDialer
	schema string
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	return fmt.Sprintf("%s://%s", c.schema, net.JoinHostPort(c.host, c.port))
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if owner := resolverOwner(ctx); owner != nil {
		return c.exchangeOwned(ctx, m, owner)
	}
	ctx, finishRequest, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finishRequest()
	network := "udp"
	if c.schema != "udp" {
		network = "tcp"
	}

	addr := net.JoinHostPort(c.host, c.port)
	conn, err := c.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	workCtx, finish, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		defer finish()
		dClient := &D.Client{
			UDPSize: 4096,
			Timeout: 5 * time.Second,
		}
		dConn := &D.Conn{
			Conn:    conn,
			UDPSize: dClient.UDPSize,
		}

		msg, _, err := dClient.ExchangeWithConn(m, dConn)

		// Resolvers MUST resend queries over TCP if they receive a truncated UDP response (with TC=1 set)!
		if msg != nil && msg.Truncated && network == "udp" {
			network = "tcp"
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			var tcpConn net.Conn
			tcpConn, err = c.dialer.DialContext(workCtx, network, addr)
			if err != nil {
				ch <- result{msg, err}
				return
			}
			defer tcpConn.Close()
			dConn.Conn = tcpConn
			msg, _, err = dClient.ExchangeWithConn(m, dConn)
		}

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

// Owned candidates join the actual miekg read. Individual query cancellation
// closes its socket; instance cancellation additionally joins shared work.
func (c *client) exchangeOwned(ctx context.Context, m *D.Msg, owner *ResolverOwner) (*D.Msg, error) {
	ctx, finish, err := owner.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	ctx, finishNetwork, err := forwarding.AcquireManagementNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finishNetwork()
	network := "udp"
	if c.schema != "udp" {
		network = "tcp"
	}
	addr := net.JoinHostPort(c.host, c.port)
	for {
		raw, err := c.dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn, err := owner.ownConn(raw)
		if err != nil {
			return nil, err
		}
		callbackDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(callbackDone); _ = conn.Close() })
		dClient := &D.Client{UDPSize: 4096, Timeout: 5 * time.Second}
		var messageConn net.Conn = conn
		if network == "udp" {
			messageConn = &connectedDNSUDP{Conn: conn}
		}
		msg, _, err := dClient.ExchangeWithConn(m, &D.Conn{Conn: messageConn, UDPSize: dClient.UDPSize})
		_ = conn.Close()
		if !stop() {
			<-callbackDone
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if msg != nil && msg.Truncated && network == "udp" {
			network = "tcp"
			continue
		}
		return msg, err
	}
}

// The ownership wrapper must retain the UDP transport trait. miekg otherwise
// mistakes a connected datagram socket for TCP and adds a two-byte frame.
type connectedDNSUDP struct{ net.Conn }

func (c *connectedDNSUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *connectedDNSUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && addr.String() != c.RemoteAddr().String() {
		return 0, fmt.Errorf("DNS datagram destination changed")
	}
	return c.Write(p)
}

func (c *client) ResetConnection() {}

func newClient(addr string, resolver resolver.Resolver, netType string, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *client {
	host, port, _ := net.SplitHostPort(addr)
	c := &client{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
		schema: "udp",
	}
	if strings.HasPrefix(netType, "tcp") {
		c.schema = "tcp"
	}
	return c
}
