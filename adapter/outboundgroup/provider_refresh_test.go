package outboundgroup

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Membership and refresh use a real file-backed provider. These counters only
// identify which same-name object received each real loopback dial.
type refreshChoiceProxy struct {
	*selectionTestProxy
	tcpCalls atomic.Int32
	udpCalls atomic.Int32
}

func refreshProxy(name string) *refreshChoiceProxy {
	return &refreshChoiceProxy{selectionTestProxy: selectionProxy(name, true)}
}

func (p *refreshChoiceProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.tcpCalls.Add(1)
	return p.Proxy.DialContext(ctx, metadata)
}

func (p *refreshChoiceProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	p.udpCalls.Add(1)
	return p.Proxy.ListenPacketContext(ctx, metadata)
}

func refreshEchoServer(t *testing.T) *C.Metadata {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	metadata := &C.Metadata{NetWork: C.TCP}
	if err := metadata.SetRemoteAddress(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestProviderRefreshImmediatelyChangesActualURLTestDial(t *testing.T) {
	for _, selection := range []string{"automatic", "legacy", "qualified"} {
		t.Run(selection, func(t *testing.T) {
			old, replacement := refreshProxy("same-name"), refreshProxy("same-name")
			pd, refresh := selectionProvider(t, "P", map[string][]C.Proxy{
				"initial": {old}, "replacement": {replacement},
			})
			group := selectionTestGroup(t, "urltest", GroupCommonOption{}, pd)
			switch selection {
			case "legacy":
				if err := group.Set(old.Name()); err != nil {
					t.Fatal(err)
				}
			case "qualified":
				if err := group.SetIdentity(old, pd); err != nil {
					t.Fatal(err)
				}
			}
			metadata := refreshEchoServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			live, err := group.DialContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer live.Close()
			if old.tcpCalls.Load() != 1 {
				t.Fatal("initial dial did not use the old object")
			}

			refresh("replacement")
			next, err := group.DialContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			pc, err := group.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			if old.tcpCalls.Load() != 1 || old.udpCalls.Load() != 0 || replacement.tcpCalls.Load() != 1 || replacement.udpCalls.Load() != 1 {
				t.Fatalf("new calls used stale object: old TCP/UDP=%d/%d, replacement=%d/%d", old.tcpCalls.Load(), old.udpCalls.Load(), replacement.tcpCalls.Load(), replacement.udpCalls.Load())
			}
			if group.SelectedProxy() != replacement {
				t.Fatal("reported selection disagrees with the new provider object")
			}
			if err := live.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := live.Write([]byte("alive")); err != nil {
				t.Fatalf("refresh killed existing TCP connection: %v", err)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(live, buf); err != nil || string(buf) != "alive" {
				t.Fatalf("existing connection lost after refresh: %q, %v", buf, err)
			}
		})
	}
}

func TestProviderRefreshChangesAutomaticGroupMembers(t *testing.T) {
	for _, kind := range []string{"urltest", "fallback", "load-balance"} {
		t.Run(kind, func(t *testing.T) {
			old, replacement := selectionProxy("old", true), selectionProxy("new", true)
			pd, refresh := selectionProvider(t, "P", map[string][]C.Proxy{
				"initial": {old}, "replacement": {replacement},
			})
			var group C.ProxyAdapter
			if kind == "load-balance" {
				var err error
				group, err = NewLoadBalance(GroupCommonOption{Name: "load", URL: "https://synthetic.invalid/"}, LoadBalanceOption{Strategy: "round-robin"}, selectionProxy("empty", true), []P.ProxyProvider{pd})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				group = selectionTestGroup(t, kind, GroupCommonOption{}, pd)
			}
			if got := group.Unwrap(nil, true); got != old {
				t.Fatal("initial member was not selected")
			}
			refresh("replacement")
			if got := group.Unwrap(nil, true); got != replacement {
				t.Fatal("refresh retained an object no longer in the provider")
			}
		})
	}
}
