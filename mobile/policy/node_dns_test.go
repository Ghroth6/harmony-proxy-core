package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	SS "github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
)

func publicAuthenticatedSSPeer(t *testing.T) (int, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := SS.PickCipher("aes-128-gcm", nil, "documentation-password")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
		conn := cipher.StreamConn(raw)
		if _, err = socks5.ReadAddr0(conn); err == nil {
			payload := make([]byte, len("public-policy-request"))
			_, err = io.ReadFull(conn, payload)
			if err == nil && string(payload) != "public-policy-request" {
				err = fmt.Errorf("authenticated request changed")
			}
			if err == nil {
				_, err = conn.Write([]byte("public-policy-answer"))
			}
		}
		result <- err
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().(*net.TCPAddr).Port, result
}

// All activation goes through the actual published candidate, forwarding gate
// and submitted non-VPN snapshot. Neither resolver nor adapter is substituted.
func activatePublicPolicy(t *testing.T, cfg *config.Config, servers []string, protected *atomic.Int32, deferGroups ...bool) (context.Context, uint64) {
	t.Helper()
	generation := publicProtectedPolicy(t, func(uint64, uint64, uintptr) int32 {
		protected.Add(1)
		return protection.Success
	})
	previous, _ := platformnetwork.Current()
	encoded, _ := json.Marshal(servers)
	snapshot := []byte(fmt.Sprintf(`{"schemaVersion":1,"generation":%d,"networkId":1,"vpn":false,"online":true,"dns":%s,"interfaces":[{"name":"public-loopback","mtu":1500,"up":true,"addresses":["127.0.0.1/8"],"routes":[{"destination":"0.0.0.0/0"}]}]}`, previous.Generation+1, encoded))
	if network.NewController(nil).Submit("public-policy-network", snapshot).Category != "published" {
		t.Fatal("actual platform snapshot rejected")
	}
	ctx, cancel := context.WithCancel(protection.WithGeneration(context.Background(), generation))
	tunnel.EnableForwardingLifecycle()
	if err := tunnel.PrepareForwarding(ctx, generation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cfg.CancelMobilePolicyServices()
		wait, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := cfg.WaitMobilePolicyServices(wait); err != nil {
			t.Error(err)
		}
		tunnel.CancelForwarding()
		if err := tunnel.StopForwarding(wait); err != nil {
			t.Error(err)
		}
		if err := executor.RetireConfig(wait); err != nil {
			t.Error(err)
		}
	})
	if err := cfg.ActivateMobileNetwork(generation); err != nil {
		t.Fatal(err)
	}
	if err := executor.PublishMobilePolicy(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.ActivateForwarding(generation); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ActivateMobilePolicyDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if len(deferGroups) == 0 || !deferGroups[0] {
		if err := executor.ActivateMobilePolicy(cfg); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, generation
}

func TestSourceDomainNodeUsesCapturedProxyDNSRatherThanSystemOrMutableGlobal(t *testing.T) {
	port, peerResult := publicAuthenticatedSSPeer(t)
	main, mainQueries := publicDNSPeer(t, "127.0.0.2")
	proxy, proxyQueries := publicDNSPeer(t, "127.0.0.1")
	system, systemQueries := publicDNSPeer(t, "127.0.0.2")
	input := []byte(fmt.Sprintf(`ipv6: false
profile: {store-fake-ip: false}
proxies:
 - {name: PublicNode, type: ss, server: documentation-node.example, port: %d, cipher: aes-128-gcm, password: documentation-password}
dns:
 enable: true
 ipv6: false
 enhanced-mode: redir-host
 nameserver: ['%s']
 default-nameserver: ['127.0.0.1']
 proxy-server-nameserver: ['%s']
rules: ['MATCH,PublicNode']
`, port, main, proxy))
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	platform := publicPlatform()
	platform.RuntimeOptions.DNS = true
	platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
	prepared, err := contract.Seal(contract.Digest(input), nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseline := engine.ResourceAcquireCount()
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var protected atomic.Int32
	root, _ := activatePublicPolicy(t, cfg, []string{system}, &protected)
	global := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = nil
	defer func() { resolver.ProxyServerHostResolver = global }()
	ctx, cancel := context.WithTimeout(root, time.Second)
	defer cancel()
	conn, err := cfg.Proxies["PublicNode"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
	if err != nil {
		t.Fatalf("original node must dial via captured proxy nameserver: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte("public-policy-request")); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, len("public-policy-answer"))
	if _, err = io.ReadFull(conn, answer); err != nil || string(answer) != "public-policy-answer" {
		t.Fatalf("authenticated original-node response: %v", err)
	}
	if err = <-peerResult; err != nil {
		t.Fatal(err)
	}
	if proxyQueries.Load() != 1 || mainQueries.Load() != 0 || systemQueries.Load() != 0 || protected.Load() < 2 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("captured DNS and node socket must be protected, with no system fallback or resource GET")
	}
}

func TestDNSDisabledDomainBootstrapRetiresItsActualSharedQuery(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{}, 1)
	server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(D.ResponseWriter, *D.Msg) {
		select {
		case seen <- struct{}{}:
		default:
		}
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	input := []byte(`ipv6: false
dns: {enable: false}
proxies:
 - {name: PublicNode, type: ss, server: cancel-documentation.example, port: 8388, cipher: aes-128-gcm, password: documentation-password}
rules: ['MATCH,PublicNode']
`)
	prepared, err := contract.Seal(contract.Digest(input), nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MobileDNSService() != nil {
		t.Fatal("system bootstrap must not invent enabled client DNS")
	}
	var protected atomic.Int32
	root, _ := activatePublicPolicy(t, cfg, []string{packet.LocalAddr().String()}, &protected)
	dialContext, stopDial := context.WithTimeout(root, 3*time.Second)
	defer stopDial()
	result := make(chan error, 1)
	go func() {
		conn, err := cfg.Proxies["PublicNode"].DialContext(dialContext, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("actual system DNS peer did not receive node bootstrap")
	}
	cfg.CancelMobilePolicyServices()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = cfg.WaitMobilePolicyServices(wait); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-result:
		if err == nil || protected.Load() == 0 {
			t.Fatal("retired owned system query must fail and its socket must be protected")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("service retirement reported clean while the actual node DNS waiter remained pending")
	}
}
