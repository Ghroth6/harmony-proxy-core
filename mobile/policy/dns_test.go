package policy_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func publicDNSPeer(t *testing.T, address string) (string, *atomic.Int32) {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, m *D.Msg) {
		count.Add(1)
		response := new(D.Msg)
		response.SetReply(m)
		answer, err := D.NewRR(m.Question[0].Name + " 60 IN A " + address)
		if err != nil {
			t.Error(err)
			return
		}
		response.Answer = []D.RR{answer}
		_ = w.WriteMsg(response)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	return packet.LocalAddr().String(), count
}

func TestOriginalDNSPolicyUsesCapturedServiceScopedGeoAndActualProtectedQueries(t *testing.T) {
	main, mainQueries := publicDNSPeer(t, "192.0.2.10")
	selected, selectedQueries := publicDNSPeer(t, "192.0.2.20")
	input := []byte(fmt.Sprintf(`ipv6: false
profile: {store-fake-ip: false}
hosts: {'pinned-documentation.example': 192.0.2.44}
dns:
 enable: true
 ipv6: false
 enhanced-mode: redir-host
 nameserver: ['%s']
 default-nameserver: ['127.0.0.1']
 nameserver-policy: {'geosite:DOC': ['%s']}
rules: ['MATCH,DIRECT']
`, main, selected))
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	plan := engine.Plan("dns-original-plan", input, nil)
	site, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "documentation.example"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	resource := savePublicResource(t, root, plan.Requirements[0], site)
	platform := publicPlatform()
	platform.RuntimeOptions.DNS = true
	platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseline := engine.ResourceAcquireCount()
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatalf("actual original DNS candidate: %s", err)
	}
	accessor, ok := any(cfg).(interface {
		MobileDNSService() *dns.Service
		ActivateMobilePolicyDNS(context.Context) error
	})
	if !ok {
		_ = cfg.Discard(context.Background())
		t.Fatal("source candidate must expose its own captured DNS service")
	}
	service := accessor.MobileDNSService()
	question := new(D.Msg)
	question.SetQuestion("a.documentation.example.", D.TypeA)
	if service == nil {
		t.Fatal("original DNS service was not constructed")
	}
	if _, err := service.ServeMsg(context.Background(), question); err == nil {
		t.Fatal("preparation must not admit DNS lookup")
	}
	var protected atomic.Int32
	generation := publicProtectedPolicy(t, func(uint64, uint64, uintptr) int32 { protected.Add(1); return protection.Success })
	previous, _ := platformnetwork.Current()
	ng := previous.Generation + 1
	snapshot := []byte(fmt.Sprintf(`{"schemaVersion":1,"generation":%d,"networkId":1,"vpn":false,"online":true,"dns":[],"interfaces":[{"name":"public-loopback","mtu":1500,"up":true,"addresses":["127.0.0.1/8"],"routes":[{"destination":"0.0.0.0/0"}]}]}`, ng))
	if network.NewController(nil).Submit("dns-original-network", snapshot).Category != "published" {
		t.Fatal("actual snapshot")
	}
	ctx, cancel := context.WithCancel(protection.WithGeneration(context.Background(), generation))
	defer cancel()
	tunnel.EnableForwardingLifecycle()
	if err = tunnel.PrepareForwarding(ctx, generation); err != nil {
		t.Fatal(err)
	}
	defer func() {
		tunnel.CancelForwarding()
		if err := tunnel.StopForwarding(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err = cfg.ActivateMobileNetwork(generation); err != nil {
		t.Fatal(err)
	}
	if err = executor.PublishMobilePolicy(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := executor.RetireConfig(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err = accessor.ActivateMobilePolicyDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if err = tunnel.ActivateForwarding(generation); err != nil {
		t.Fatal(err)
	}
	if err = executor.ActivateMobilePolicy(cfg); err != nil {
		t.Fatal(err)
	}
	response, err := service.ServeMsg(ctx, question)
	if err != nil || len(response.Answer) != 1 || !strings.Contains(response.Answer[0].String(), "192.0.2.20") || selectedQueries.Load() != 1 || mainQueries.Load() != 0 || protected.Load() == 0 {
		t.Fatalf("actual scoped original DNS policy was not used: %v", err)
	}
	if engine.ResourceAcquireCount() != baseline {
		t.Fatal("DNS queries must not download subscription resources")
	}
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	global := resolver.DefaultService
	resolver.DefaultService = nil
	packet, err := resolver.RelayDnsPacketWithService(ctx, payload, make([]byte, 2048), service)
	resolver.DefaultService = global
	var relayed D.Msg
	if err != nil || relayed.Unpack(packet) != nil || len(relayed.Answer) != 1 {
		t.Fatal("captured packet relay must use its candidate service rather than current global")
	}
	cfg.CancelMobilePolicyServices()
	if err = cfg.WaitMobilePolicyServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ServeMsg(ctx, question); err == nil {
		t.Fatal("captured retired service must not succeed through cache/hosts or another global service")
	}
	if _, err = resolver.RelayDnsPacketWithService(ctx, payload, make([]byte, 2048), service); err == nil {
		t.Fatal("captured retired relay must retain the service error rather than manufacture SERVFAIL success")
	}
	if err = executor.RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resolver.DefaultService != nil || resolver.DefaultHostMapper != nil || resolver.DefaultResolver != nil {
		t.Fatal("confirmed policy retirement must remove the old published DNS owner before another candidate can use it")
	}
	if _, exists := resolver.DefaultHosts.Search("pinned-documentation.example", false); exists {
		t.Fatal("retired original hosts cannot leak into a later fixed-node runtime")
	}
}
