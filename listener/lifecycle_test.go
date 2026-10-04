package listener

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/lifecycle"
)

func reserveTCP(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func reserveUDP(t *testing.T) net.PacketConn {
	t.Helper()
	// Select a port that TCP can use too (Windows UDP's ephemeral range may
	// contain ports excluded from TCP). This setup is not a readiness check.
	for attempt := 0; attempt < 2048; attempt++ {
		l, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err := net.Listen("tcp4", l.LocalAddr().String())
		if err != nil {
			_ = l.Close()
			continue
		}
		_ = tcp.Close()
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	t.Fatal("could not reserve a port usable by both TCP and UDP")
	return nil
}

func listenerPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertTCPReleased(t *testing.T, addr string) {
	t.Helper()
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("TCP socket not released at %s: %v", addr, err)
	}
	_ = l.Close()
}

func assertUDPReleased(t *testing.T, addr string) {
	t.Helper()
	l, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatalf("UDP socket not released at %s: %v", addr, err)
	}
	_ = l.Close()
}

func namedHTTP(t *testing.T, name string, port int) C.InboundListener {
	t.Helper()
	l, err := ParseListener(map[string]any{"type": "http", "name": name, "listen": "127.0.0.1", "port": strconv.Itoa(port)})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestListenerLifecycleRecreateReportsTCPBindFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		create func(int, C.Tunnel) error
	}{
		{"http", ReCreateHTTP}, {"socks", ReCreateSocks}, {"mixed", ReCreateMixed},
		{"redir", ReCreateRedir}, {"tproxy", ReCreateTProxy},
	} {
		t.Run(test.name, func(t *testing.T) {
			blocker := reserveTCP(t)
			port := listenerPort(t, blocker.Addr())
			if err := test.create(port, nil); err == nil {
				t.Fatal("occupied TCP port reported ready")
			}
			if ports := GetPorts(); *ports != (Ports{}) {
				t.Fatalf("failed listener registered: %+v", ports)
			}
			if err := test.create(0, nil); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

func TestListenerLifecyclePairRollbackAndRestart(t *testing.T) {
	for _, test := range []struct {
		name   string
		create func(int, C.Tunnel) error
	}{{"socks", ReCreateSocks}, {"mixed", ReCreateMixed}} {
		t.Run(test.name, func(t *testing.T) {
			blocker := reserveUDP(t)
			addr := blocker.LocalAddr().String()
			port := listenerPort(t, blocker.LocalAddr())
			t.Cleanup(func() { _ = test.create(0, nil) })
			if err := test.create(port, nil); err == nil {
				t.Fatal("occupied UDP port reported ready")
			}
			assertTCPReleased(t, addr)
			if ports := GetPorts(); *ports != (Ports{}) {
				t.Fatalf("partial pair registered: %+v", ports)
			}
			_ = blocker.Close()
			for i := 0; i < 2; i++ {
				if err := test.create(port, nil); err != nil {
					t.Fatalf("restart %d: %v", i, err)
				}
				if err := test.create(port, nil); err != nil {
					t.Fatalf("same config: %v", err)
				}
				if err := test.create(0, nil); err != nil {
					t.Fatal(err)
				}
				if err := test.create(0, nil); err != nil {
					t.Fatalf("repeated stop: %v", err)
				}
				assertTCPReleased(t, addr)
				assertUDPReleased(t, addr)
			}
		})
	}
}

func TestListenerLifecycleInvalidProtocolConfig(t *testing.T) {
	if err := ReCreateShadowSocks("invalid", nil); err == nil {
		t.Fatal("bad SS config accepted")
	}
	if err := ReCreateShadowSocks("ss://invalid-cipher:password@127.0.0.1:0", nil); err == nil {
		t.Fatal("invalid legacy SS cipher accepted")
	}
	if GetPorts().ShadowSocksConfig != "" {
		t.Fatal("failed legacy SS constructor registered a typed nil")
	}
	if err := ReCreateVmess("invalid", nil); err == nil {
		t.Fatal("bad VMess config accepted")
	}
	if err := ReCreateTuic(LC.TuicServer{Enable: true, Listen: "127.0.0.1:0", Certificate: "missing-cert", PrivateKey: "missing-key"}, nil); err == nil {
		t.Fatal("invalid TUIC TLS accepted")
	}
	if GetTuicConf().Enable || LastTuicConf.Enable {
		t.Fatal("failed TUIC start retained ready config")
	}
	if err := errors.Join(ReCreateShadowSocks("", nil), ReCreateVmess("", nil), ReCreateTuic(LC.TuicServer{}, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestListenerLifecycleNamedBatchRollback(t *testing.T) {
	first := reserveTCP(t)
	firstAddr := first.Addr().String()
	firstPort := listenerPort(t, first.Addr())
	_ = first.Close()
	blocker := reserveTCP(t)
	next := map[string]C.InboundListener{
		"a": namedHTTP(t, "a", firstPort),
		"b": namedHTTP(t, "b", listenerPort(t, blocker.Addr())),
	}
	t.Cleanup(func() { _ = PatchInboundListeners(nil, nil, true) })
	if err := PatchInboundListeners(next, nil, true); err == nil {
		t.Fatal("failed batch reported ready")
	}
	if len(inboundListeners) != 0 {
		t.Fatal("partial batch registered")
	}
	assertTCPReleased(t, firstAddr)
	_ = blocker.Close()
	for i := 0; i < 2; i++ {
		if err := PatchInboundListeners(next, nil, true); err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if len(inboundListeners) != 2 {
			t.Fatal("successful batch missing listeners")
		}
		if err := PatchInboundListeners(nil, nil, true); err != nil {
			t.Fatal(err)
		}
		if err := PatchInboundListeners(nil, nil, true); err != nil {
			t.Fatalf("repeated stop: %v", err)
		}
	}
	assertTCPReleased(t, firstAddr)
}

func TestListenerLifecycleFailedReplacementNotReady(t *testing.T) {
	oldSocket := reserveTCP(t)
	oldPort := listenerPort(t, oldSocket.Addr())
	oldAddr := oldSocket.Addr().String()
	_ = oldSocket.Close()
	old := namedHTTP(t, "test", oldPort)
	if err := PatchInboundListeners(map[string]C.InboundListener{"test": old}, nil, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = PatchInboundListeners(nil, nil, true) })
	blocker := reserveTCP(t)
	next := namedHTTP(t, "test", listenerPort(t, blocker.Addr()))
	if err := PatchInboundListeners(map[string]C.InboundListener{"test": next}, nil, true); err == nil {
		t.Fatal("failed replacement reported success")
	}
	if len(inboundListeners) != 0 {
		t.Fatal("closed old listener still registered")
	}
	assertTCPReleased(t, oldAddr)
}

type failCloseInbound struct {
	C.InboundListener
	failures      int
	failure       error
	listenFailure error
}

func (l *failCloseInbound) Close() error {
	if l.failures > 0 {
		l.failures--
		return l.failure
	}
	return l.InboundListener.Close()
}

func (l *failCloseInbound) Listen(tunnel C.Tunnel) error {
	if err := l.InboundListener.Listen(tunnel); err != nil {
		return err
	}
	return l.listenFailure
}

func TestListenerLifecycleCloseFailureRetainsCleanupOwnership(t *testing.T) {
	for _, failListen := range []bool{false, true} {
		t.Run(fmt.Sprint(failListen), func(t *testing.T) {
			socket := reserveTCP(t)
			addr, port := socket.Addr().String(), listenerPort(t, socket.Addr())
			_ = socket.Close()
			closeFailure := errors.New("close temporarily failed")
			l := &failCloseInbound{InboundListener: namedHTTP(t, "test", port), failures: 1, failure: closeFailure}
			if failListen {
				l.listenFailure = errors.New("failure after partial Listen")
			}
			startErr := PatchInboundListeners(map[string]C.InboundListener{"test": l}, nil, true)
			t.Cleanup(func() { _ = PatchInboundListeners(nil, nil, true) })
			var closeErr error
			if failListen {
				closeErr = startErr
			} else {
				if startErr != nil {
					t.Fatal(startErr)
				}
				closeErr = PatchInboundListeners(nil, nil, true)
			}
			if !errors.Is(closeErr, closeFailure) {
				t.Fatalf("close error lost: %v", closeErr)
			}
			if len(inboundListeners) != 0 || len(inboundPendingClose) != 1 {
				t.Fatal("failed close is ready or lost")
			}
			if err := PatchInboundListeners(nil, nil, true); err != nil {
				t.Fatalf("cleanup retry: %v", err)
			}
			if len(inboundPendingClose) != 0 {
				t.Fatal("cleanup retry retained closed object")
			}
			assertTCPReleased(t, addr)
		})
	}
}

func TestListenerLifecycleTunnelRollbackAndRestart(t *testing.T) {
	blocker := reserveUDP(t)
	addr := blocker.LocalAddr().String()
	config := []LC.Tunnel{{Network: []string{"tcp", "udp"}, Address: addr, Target: "127.0.0.1:9", Proxy: "DIRECT"}}
	t.Cleanup(func() { _ = PatchTunnel(nil, nil) })
	if err := PatchTunnel(config, nil); err == nil {
		t.Fatal("occupied UDP tunnel reported ready")
	}
	if len(tunnelTCPListeners) != 0 || len(tunnelUDPListeners) != 0 {
		t.Fatal("partial tunnel registered")
	}
	assertTCPReleased(t, addr)
	_ = blocker.Close()
	for i := 0; i < 2; i++ {
		if err := PatchTunnel(config, nil); err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if err := PatchTunnel(config, nil); err != nil {
			t.Fatal(err)
		}
		if err := PatchTunnel(nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := PatchTunnel(nil, nil); err != nil {
			t.Fatalf("repeated stop: %v", err)
		}
		assertTCPReleased(t, addr)
		assertUDPReleased(t, addr)
	}
}

func TestListenerLifecycleCloseJoinKeepsRealFailure(t *testing.T) {
	failure := errors.New("close failed")
	if err := lifecycle.CloseError(errors.Join(net.ErrClosed, failure)); !errors.Is(err, failure) {
		t.Fatalf("real error hidden: %v", err)
	}
	if err := lifecycle.CloseError(fmt.Errorf("close listener: %w", net.ErrClosed)); err != nil {
		t.Fatal(err)
	}
}

func TestListenerLifecyclePendingCloseDoesNotBlockOtherStops(t *testing.T) {
	first, second := reserveTCP(t), reserveTCP(t)
	firstAddr, secondAddr := first.Addr().String(), second.Addr().String()
	firstPort, secondPort := listenerPort(t, first.Addr()), listenerPort(t, second.Addr())
	_ = first.Close()
	_ = second.Close()
	failure := errors.New("close temporarily failed")
	a := &failCloseInbound{InboundListener: namedHTTP(t, "a", firstPort), failures: 2, failure: failure}
	b := namedHTTP(t, "b", secondPort)
	t.Cleanup(func() { _ = PatchInboundListeners(nil, nil, true) })
	if err := PatchInboundListeners(map[string]C.InboundListener{"a": a, "b": b}, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := PatchInboundListeners(map[string]C.InboundListener{"b": b}, nil, true); !errors.Is(err, failure) {
		t.Fatalf("close error lost: %v", err)
	}
	if len(inboundListeners) != 1 || len(inboundPendingClose) != 1 {
		t.Fatal("test needs both active and pending listeners")
	}
	if err := PatchInboundListeners(nil, nil, true); !errors.Is(err, failure) {
		t.Fatalf("pending close error lost: %v", err)
	}
	if len(inboundListeners) != 0 {
		t.Fatal("pending failure skipped closing active listener")
	}
	assertTCPReleased(t, secondAddr)
	if err := PatchInboundListeners(nil, nil, true); err != nil {
		t.Fatal(err)
	}
	assertTCPReleased(t, firstAddr)
}

func TestListenerLifecycleProtocolBindFailureAndRestart(t *testing.T) {
	for _, test := range []struct {
		name   string
		url    func(string) string
		create func(string, C.Tunnel) error
	}{
		{"shadowsocks", func(addr string) string { return "ss://none:password@" + addr }, ReCreateShadowSocks},
		{"vmess", func(addr string) string { return "vmess://test:11111111-1111-1111-1111-111111111111@" + addr }, ReCreateVmess},
	} {
		t.Run(test.name, func(t *testing.T) {
			udp := reserveUDP(t)
			addr := udp.LocalAddr().String()
			_ = udp.Close()
			blocker, err := net.Listen("tcp4", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = blocker.Close(); _ = test.create("", nil) })
			if err := test.create(test.url(addr), nil); err == nil {
				t.Fatal("TCP bind failure reported ready")
			}
			if ports := GetPorts(); ports.ShadowSocksConfig != "" || ports.VmessConfig != "" {
				t.Fatal("failed protocol listener registered")
			}
			assertUDPReleased(t, addr)
			_ = blocker.Close()
			if err := test.create(test.url(addr), nil); err != nil {
				t.Fatalf("restart: %v", err)
			}
			if err := test.create(test.url(addr), nil); err != nil {
				t.Fatalf("same config: %v", err)
			}
			if err := test.create("", nil); err != nil {
				t.Fatal(err)
			}
			if err := test.create("", nil); err != nil {
				t.Fatalf("repeated stop: %v", err)
			}
			assertTCPReleased(t, addr)
			assertUDPReleased(t, addr)
		})
	}
}

func TestListenerLifecycleRecreateCloseFailureRetainsOwnership(t *testing.T) {
	failure := errors.New("close failed")
	l := &failCloseInbound{failures: 1, failure: failure}
	// This helper backs each ReCreate global slot. Failed Close clears readiness
	// but keeps the closer available for the next call, even when the slot is nil.
	socket := reserveTCP(t)
	addr := socket.Addr().String()
	port := listenerPort(t, socket.Addr())
	_ = socket.Close()
	l.InboundListener = namedHTTP(t, "test", port)
	if err := l.Listen(nil); err != nil {
		t.Fatal(err)
	}
	slot := l
	t.Cleanup(func() { _ = closeAndClear(&slot) })
	if err := closeAndClear(&slot); !errors.Is(err, failure) {
		t.Fatalf("close error lost: %v", err)
	}
	if slot != nil {
		t.Fatal("failed close still ready")
	}
	if err := closeAndClear(&slot); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertTCPReleased(t, addr)
}
