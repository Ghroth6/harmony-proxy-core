package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

var dnsDefaultTTL uint32 = 600

type Server struct {
	mu      sync.RWMutex
	service resolver.Service
	run     *externalRun
	tcp     *dnsEndpoint
	udp     *dnsEndpoint
}

type serverHandler struct {
	*Server
	isUDP bool
}

func (s serverHandler) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	ctx, finish, err := s.run.begin(context.Background())
	if err != nil {
		return
	}
	defer finish()
	s.mu.RLock()
	service := s.service
	s.mu.RUnlock()
	msg, err := service.ServeMsg(ctx, r)
	// A resolver may finish concurrently with cancellation or ignore its context.
	// Never publish its late result into a retired external run.
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		msg = new(D.Msg)
		msg.SetRcode(r, D.RcodeServerFailure)
	}
	if s.isUDP {
		msg.Truncate(resolver.RequestUDPSize(r))
	}
	msg.Compress = true
	_ = w.WriteMsg(msg)
}

func (s *Server) UDPHandler() D.Handler { return serverHandler{Server: s, isUDP: true} }
func (s *Server) TCPHandler() D.Handler { return serverHandler{Server: s} }
func (s *Server) SetService(service resolver.Service) {
	s.mu.Lock()
	s.service = service
	s.mu.Unlock()
}

// ReCreateServer applies the external DNS configuration. In managed mode it
// records the next run's configuration without opening ingress. Internal
// resolver/service globals are deliberately not owned here.
func ReCreateServer(addr string, lc C.InboundListenConfig, service resolver.Service) error {
	external.opMu.Lock()
	defer external.opMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()
	if err := external.stop(ctx); err != nil {
		return err
	}
	external.config = externalConfig{addr: addr, lc: lc, service: service}
	if external.isManaged() {
		return nil
	}
	return external.start(context.Background())
}

// closeOwner retains a failed close for an explicit cleanup retry. Library
// deferred closes cannot hide a failure or erase the resource reference.
type closeOwner struct {
	mu        sync.Mutex
	close     func() error
	attempted bool
	err       error
}

func (o *closeOwner) Close() error { return o.tryClose(false) }
func (o *closeOwner) tryClose(retry bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.attempted && (!retry || o.err == nil) {
		return o.err
	}
	o.attempted = true
	o.err = o.close()
	if errors.Is(o.err, net.ErrClosed) {
		o.err = nil
	}
	return o.err
}

type ownedDNSConn struct {
	net.Conn
	owner    closeOwner
	released func()
}

func (c *ownedDNSConn) Close() error {
	err := c.owner.Close()
	if err == nil {
		c.released()
	}
	return err
}

type ownedDNSListener struct {
	net.Listener
	owner closeOwner
	mu    sync.Mutex
	conns map[*ownedDNSConn]struct{}
}

func (l *ownedDNSListener) Close() error { return l.owner.Close() }
func (l *ownedDNSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	owned := &ownedDNSConn{Conn: c, owner: closeOwner{close: c.Close}}
	owned.released = func() { l.mu.Lock(); delete(l.conns, owned); l.mu.Unlock() }
	l.mu.Lock()
	l.conns[owned] = struct{}{}
	l.mu.Unlock()
	return owned, nil
}
func (l *ownedDNSListener) closeConnections() error {
	l.mu.Lock()
	conns := make([]*ownedDNSConn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	var errs []error
	for _, c := range conns {
		if err := c.owner.tryClose(true); err != nil {
			errs = append(errs, err)
		} else {
			c.released()
		}
	}
	return errors.Join(errs...)
}

type dnsEndpoint struct {
	server       *D.Server
	owner        *closeOwner
	tcp          *ownedDNSListener
	serveDone    chan struct{}
	serveErr     error
	started      bool
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
}

func (e *dnsEndpoint) activate() error {
	ready := make(chan struct{})
	e.server.NotifyStartedFunc = func() { close(ready) }
	go func() {
		e.serveErr = e.server.ActivateAndServe()
		close(e.serveDone)
	}()
	select {
	case <-ready:
		e.started = true
		return nil
	case <-e.serveDone:
		return fmt.Errorf("activate DNS listener: %w", e.serveErr)
	}
}

func (e *dnsEndpoint) stop(ctx context.Context) error {
	if e == nil {
		return nil
	}
	// Close ourselves: miekg/dns discards socket Close errors. Keep UDP's
	// concrete *net.UDPConn so its destination-address/OOB behavior survives.
	closeErr := e.owner.tryClose(true)
	var connErr error
	if e.tcp != nil {
		connErr = e.tcp.closeConnections()
	}
	if e.started {
		e.shutdownOnce.Do(func() {
			go func() {
				e.shutdownErr = e.server.Shutdown()
				close(e.shutdownDone)
			}()
		})
		select {
		case <-e.shutdownDone:
		case <-ctx.Done():
			return errors.Join(closeErr, connErr, ctx.Err())
		}
	}
	select {
	case <-e.serveDone:
	case <-ctx.Done():
		return errors.Join(closeErr, connErr, ctx.Err())
	}
	// Accept may have returned just before the listening socket was closed.
	if e.tcp != nil {
		connErr = errors.Join(connErr, e.tcp.closeConnections())
	}
	return errors.Join(closeErr, connErr, e.shutdownErr)
}

func newDNSEndpoint(s *D.Server, owner *closeOwner, tcp *ownedDNSListener) *dnsEndpoint {
	return &dnsEndpoint{server: s, owner: owner, tcp: tcp, serveDone: make(chan struct{}), shutdownDone: make(chan struct{})}
}

func (s *Server) bind(ctx context.Context, c externalConfig) error {
	if c.addr == "" || c.service == nil {
		return nil
	}
	if c.lc == nil {
		return errors.New("DNS listen config is missing")
	}
	_, port, err := net.SplitHostPort(c.addr)
	if err != nil {
		return err
	}
	if port == "" || port == "0" {
		return errors.New("DNS listen port must be nonzero")
	}
	p, err := c.lc.ListenPacket(ctx, "udp", c.addr)
	if err != nil {
		return fmt.Errorf("bind DNS UDP: %w", err)
	}
	if err := sockopt.UDPReuseaddr(p); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}
	s.udp = newDNSEndpoint(&D.Server{Addr: c.addr, PacketConn: p, Handler: s.UDPHandler()}, &closeOwner{close: p.Close}, nil)
	// Start each acquired endpoint immediately so all records share the same
	// cleanup path even if the second protocol cannot bind.
	if err := s.udp.activate(); err != nil {
		return err
	}
	l, err := c.lc.Listen(ctx, "tcp", c.addr)
	if err != nil {
		return fmt.Errorf("bind DNS TCP: %w", err)
	}
	owned := &ownedDNSListener{Listener: l, owner: closeOwner{close: l.Close}, conns: make(map[*ownedDNSConn]struct{})}
	s.tcp = newDNSEndpoint(&D.Server{Addr: c.addr, Listener: owned, Handler: s.TCPHandler()}, &owned.owner, owned)
	if err := s.tcp.activate(); err != nil {
		return err
	}
	log.Infoln("DNS server listening at: %s (UDP and TCP)", c.addr)
	return nil
}

func (s *Server) stop(ctx context.Context) error {
	var errs []error
	for _, endpoint := range []**dnsEndpoint{&s.tcp, &s.udp} {
		if *endpoint == nil {
			continue
		}
		if err := (*endpoint).stop(ctx); err != nil {
			errs = append(errs, err)
		} else {
			*endpoint = nil
		}
	}
	return errors.Join(errs...)
}

// Start/stop callers should normally supply their own operation deadline.
const externalCleanupTimeout = 5 * time.Second
