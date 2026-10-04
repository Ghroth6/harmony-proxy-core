package session_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
)

type poolProxy struct {
	*outbound.Base
	dial func(context.Context) (net.Conn, error)
}

var forwardingGeneration atomic.Uint64

func (p *poolProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(c, p), nil
}

type poolTunnel struct {
	C.Tunnel
	serve func(net.Conn)
}

func (p *poolTunnel) HandleTCPConn(c net.Conn, _ *C.Metadata) { p.serve(c) }

// Exercise the actual AnyTLS session pool, wire protocol and nested proxy dialer.
// A forwarding stream creates a session, then a management stream reuses that
// same physical connection. Stopping forwarding must not close the pooled socket.
func TestSharedAnyTLSSessionSurvivesForwardingStopAfterManagementReuse(t *testing.T) {
	for _, managementFirst := range []bool{false, true} {
		name := "forwarding-first"
		if managementFirst {
			name = "management-first"
		}
		t.Run(name, func(t *testing.T) { testSharedAnyTLSSession(t, managementFirst) })
	}
}

func testSharedAnyTLSSession(t *testing.T, managementFirst bool) {
	var pad atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	var dials atomic.Int32
	var retained context.Context
	var mu sync.Mutex
	var servers []*session.Session
	p := &poolProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "nested-proxy", Type: C.Direct})}
	p.dial = func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		retained = ctx
		return inner.HandleTcpContext(ctx, &poolTunnel{serve: func(server net.Conn) {
			s := session.NewServerSession(server, func(stream *session.Stream) { go func() { defer stream.Close(); _, _ = io.Copy(stream, stream) }() }, &pad)
			mu.Lock()
			servers = append(servers, s)
			mu.Unlock()
			s.Run()
		}}, "127.0.0.1:443", "")
	}
	client := session.NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return proxydialer.New(p, true).DialContext(ctx, "tcp", "127.0.0.1:443")
	}, &pad, "test", time.Hour, time.Hour, 1, false)
	defer func() {
		_ = client.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, s := range servers {
			_ = s.Close()
		}
	}()
	forwarding.Enable()
	if err := forwarding.Start(context.Background(), forwardingGeneration.Add(1)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := forwarding.Stop(ctx); err != nil {
			t.Error(err)
		}
	}()
	scope, finish, err := forwarding.Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	managementCaller, cancelManagement := context.WithCancel(context.Background())
	defer cancelManagement()
	firstCtx := scope
	if managementFirst {
		firstCtx = managementCaller
	}
	first, err := client.CreateStream(firstCtx)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	first, err = forwarding.OwnConn(firstCtx, first)
	finish()
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e := c.Write([]byte("hello")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 5)
		if _, e := io.ReadFull(c, b); e != nil || string(b) != "hello" {
			t.Fatalf("pool echo = %q %v", b, e)
		}
		_ = c.SetDeadline(time.Time{})
	}
	exchange(first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if managementFirst {
		cancelManagement()
		if retained.Err() != nil {
			t.Fatalf("pool retained first management cancellation: %v", retained.Err())
		}
		forwardCtx, forwardDone, err := forwarding.Acquire(scope)
		if err != nil {
			t.Fatal(err)
		}
		forwardStream, err := client.CreateStream(forwardCtx)
		if err != nil {
			forwardDone()
			t.Fatal(err)
		}
		forwardStream, err = forwarding.OwnConn(forwardCtx, forwardStream)
		forwardDone()
		if err != nil {
			t.Fatal(err)
		}
		exchange(forwardStream)
		if err := forwardStream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	management, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	exchange(management)
	if dials.Load() != 1 {
		t.Fatalf("did not reuse actual pool: %d physical dials", dials.Load())
	}
	wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwarding.Stop(wait); err != nil {
		t.Fatal(err)
	}
	if retained.Err() != nil {
		t.Fatalf("pool retained forwarding cancellation: %v", retained.Err())
	}
	exchange(management)
	if dials.Load() != 1 {
		t.Fatal("management silently replaced the shared connection")
	}
}
