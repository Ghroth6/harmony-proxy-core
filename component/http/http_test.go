package http

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

func TestHTTPBootstrapFallbackDoesNotBypassSelectedProxy(t *testing.T) {
	previous := inner.GetTunnel()
	inner.New(nil)
	t.Cleanup(func() { inner.New(previous) })
	var hits atomic.Int32
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "bootstrap")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, server.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("ordinary bootstrap path did not reach the local server")
	}
	_, err = HttpRequest(ctx, server.URL, "GET", nil, nil, WithSpecialProxy("selected-unavailable"))
	if !errors.Is(err, inner.ErrTunnelUninitialized) || hits.Load() != 1 {
		t.Fatalf("explicit proxy fell back to direct: hits=%d err=%v", hits.Load(), err)
	}
}

type contextTunnel struct {
	started chan *C.Metadata
	closed  chan struct{}
}

func (t *contextTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	t.started <- metadata
	<-metadata.RequestContext.Done()
	close(t.closed)
}
func (*contextTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (*contextTunnel) NatTable() C.NatTable                     { return nil }

func TestHTTPRequestCancellationReachesInternalTunnel(t *testing.T) {
	previous := inner.GetTunnel()
	probe := &contextTunnel{started: make(chan *C.Metadata, 1), closed: make(chan struct{})}
	inner.New(probe)
	t.Cleanup(func() { inner.New(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := HttpRequest(ctx, "http://127.0.0.1:9", "GET", nil, nil); result <- err }()
	select {
	case <-probe.started:
	case <-time.After(time.Second):
		t.Fatal("request did not enter the internal tunnel")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was replaced by another result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP caller did not cancel")
	}
	select {
	case <-probe.closed:
	case <-time.After(time.Second):
		t.Fatal("HTTP transport detached cancellation from the internal root request")
	}
}
