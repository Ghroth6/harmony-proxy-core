package provider

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

type leasedProviderAdapter struct {
	*outbound.Base
	closes  atomic.Int32
	started chan struct{}
	release <-chan struct{}
	err     error
}

func (a *leasedProviderAdapter) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(c, a), nil
}

func (a *leasedProviderAdapter) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return outbound.NewPacketConn(c, a), nil
}

func (a *leasedProviderAdapter) Close() error {
	a.closes.Add(1)
	if a.started != nil {
		close(a.started)
	}
	if a.release != nil {
		<-a.release
	}
	return a.err
}

func ownedProviderProxy(t *testing.T, name string) (*adapter.Proxy, *leasedProviderAdapter) {
	t.Helper()
	a := &leasedProviderAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Direct, UDP: true})}
	p := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(a))
	if _, ok := p.Adapter().(retiredAdapter); !ok {
		t.Fatal("native auto-close adapter has no deterministic retirement contract")
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, a
}

func refreshingProvider(t *testing.T, current, next C.Proxy) *ProxySetProvider {
	t.Helper()
	pd, err := NewProxySetProvider("refresh", 0, []map[string]any{{"name": "initial"}}, func(data []byte) ([]C.Proxy, error) {
		if string(data) == "next" {
			return []C.Proxy{next}, nil
		}
		return []C.Proxy{current}, nil
	}, resource.NewFileVehicle(filepath.Join(t.TempDir(), "nodes.yaml")), NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pd.Close() })
	return pd
}

func retireWait(t *testing.T, p C.Proxy) error {
	t.Helper()
	owner, ok := p.Adapter().(retiredAdapter)
	if !ok {
		t.Fatal("proxy adapter has no deterministic retirement contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return owner.WaitRetired(ctx)
}

func TestProviderRefreshDrainsActualTCPAndUDPWithoutClosingLiveConnections(t *testing.T) {
	current, raw := ownedProviderProxy(t, "same")
	next, _ := ownedProviderProxy(t, "same")
	pd := refreshingProvider(t, current, next)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	meta := &C.Metadata{}
	if err := meta.SetRemoteAddress(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	// A protocol pool using this node as its dialer must hold the same lease.
	tcp, err := proxydialer.New(current, false).DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	udp, err := current.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 0 || pd.Proxies()[0] != next {
		t.Fatal("refresh closed a live adapter or did not publish replacement")
	}
	if conn, err := current.DialContext(context.Background(), meta); err == nil {
		_ = conn.Close()
		t.Fatal("removed node accepted a new dial")
	}
	_ = tcp.SetDeadline(time.Now().Add(time.Second))
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	if _, err := tcp.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("old TCP connection interrupted: %q, %v", buf, err)
	}
	if _, err := udp.WriteTo([]byte("alive"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := receiver.ReadFrom(buf); err != nil || string(buf[:n]) != "alive" {
		t.Fatalf("old UDP connection interrupted: %v", err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 0 {
		t.Fatal("TCP close ignored the surviving UDP lease")
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := retireWait(t, current); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pd.waitRetiredProxies(ctx); err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 1 || len(pd.retiredProxies()) != 0 {
		t.Fatal("completed adapter retained or closed more than once")
	}
}

func TestProviderRefreshRetainsReusedAdapterButRetiresOldMeasurements(t *testing.T) {
	current, raw := ownedProviderProxy(t, "same")
	alias := adapter.NewProxy(current.Adapter())
	pd := refreshingProvider(t, current, alias)
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if _, err := current.URLTest(context.Background(), "http://unused.invalid", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("removed proxy measurement still admitted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := alias.DialContext(ctx, &C.Metadata{Host: "unused.invalid", DstPort: 443})
	if !errors.Is(err, context.Canceled) || raw.closes.Load() != 0 {
		t.Fatalf("reused adapter was retired: %v", err)
	}
}

func TestHistoricalCloseTimeoutAndErrorRemainOwnedAcrossProviderWait(t *testing.T) {
	current, raw := ownedProviderProxy(t, "old")
	next, _ := ownedProviderProxy(t, "new")
	release := make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	raw.started, raw.release = make(chan struct{}), release
	raw.err = errors.New("historical adapter close failed")
	pd := refreshingProvider(t, current, next)
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	awaitRetirement(t, raw.started)
	pd.Cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := pd.Wait(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost in-flight historical close: %v", err)
	}
	unblock.Do(func() { close(release) })
	for attempt := 0; attempt < 2; attempt++ {
		if err := pd.Wait(context.Background()); !errors.Is(err, raw.err) {
			t.Fatalf("historical error forgotten: %v", err)
		}
	}
	if _, _, err := pd.SideUpdate([]byte("another")); !errors.Is(err, raw.err) {
		t.Fatalf("update hid historical retirement error: %v", err)
	}
	if raw.closes.Load() != 1 || len(pd.retiredProxies()) != 1 {
		t.Fatal("unknown cleanup was retried or ownership was discarded")
	}
}

func TestHistoricalURLTestCallbackRemainsPartOfProviderRetirement(t *testing.T) {
	current, _ := ownedProviderProxy(t, "old")
	next, _ := ownedProviderProxy(t, "new")
	pd := refreshingProvider(t, current, next)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	callback, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	unsubscribe := adapter.SubscribeURLTests(func(event adapter.URLTestEvent) {
		if event.Proxy == current {
			close(callback)
			<-release
		}
	})
	defer unsubscribe()
	finished := make(chan struct{})
	go func() { _, _ = current.URLTest(context.Background(), server.URL, nil); close(finished) }()
	awaitRetirement(t, callback)
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	pd.Cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := pd.Wait(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("provider forgot historical result callback: %v", err)
	}
	unblock.Do(func() { close(release) })
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitRetirement(t, finished)
}

func TestProviderRefreshClosesRemovedRealAnyTLSWithoutGC(t *testing.T) {
	parser := candidateParser(t)
	pd, err := NewProxySetProvider("native", 0, []map[string]any{anyTLSCandidate("old")}, parser,
		resource.NewFileVehicle(filepath.Join(t.TempDir(), "nodes.yaml")), NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	old := pd.Proxies()[0]
	if _, _, err := pd.SideUpdate(candidatePayload(t, anyTLSCandidate("new"))); err != nil {
		t.Fatal(err)
	}
	defer pd.Proxies()[0].Close()
	if err := retireWait(t, old); err != nil {
		t.Fatal(err)
	}
	assertCandidateOpen(t, pd.Proxies()[0])
}

func TestProviderCancellationClosesActiveHistoricalTCPAndUDP(t *testing.T) {
	current, raw := ownedProviderProxy(t, "old")
	next, nextRaw := ownedProviderProxy(t, "new")
	pd := refreshingProvider(t, current, next)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	meta := &C.Metadata{}
	if err := meta.SetRemoteAddress(server.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	tcp, err := current.DialContext(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := current.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	pd.Cancel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pd.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Write([]byte("closed")); err == nil {
		t.Fatal("historical TCP remained open after provider retirement")
	}
	if _, err := udp.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Fatal("historical UDP remained open after provider retirement")
	}
	if raw.closes.Load() != 1 || nextRaw.closes.Load() != 0 {
		t.Fatal("provider retired the current executor-owned adapter or repeated an old close")
	}
}

func TestCustomParserBorrowedProxyIsNotRetiredByRefresh(t *testing.T) {
	raw := &leasedProviderAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "borrowed", Type: C.Direct})}
	borrowed := adapter.NewProxy(raw)
	next, _ := ownedProviderProxy(t, "new")
	pd := refreshingProvider(t, borrowed, next)
	if _, _, err := pd.SideUpdate([]byte("next")); err != nil {
		t.Fatal(err)
	}
	pd.Cancel()
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	if _, err := borrowed.URLTest(context.Background(), server.URL, nil); err != nil {
		t.Fatalf("refresh cancelled a borrowed object's measurements: %v", err)
	}
	if raw.closes.Load() != 0 || len(pd.retiredProxies()) != 0 {
		t.Fatal("provider assumed ownership of a custom parser's borrowed adapter")
	}
}
