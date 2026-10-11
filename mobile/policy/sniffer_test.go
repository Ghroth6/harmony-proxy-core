package policy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/tunnel"
	"google.golang.org/protobuf/proto"
)

func TestOriginalEnabledSnifferRoutesPureIPHTTPByDeclaredDomainWithoutPreparationNetwork(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "documentation.example" {
			t.Error("original Host changed")
		}
		received.Add(1)
		_, _ = w.Write([]byte("public-sniff-answer"))
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	raw := []byte(fmt.Sprintf(`ipv6: false
dns: {enable: false}
sniffer:
 enable: true
 parse-pure-ip: true
 override-destination: false
 sniff: {HTTP: {ports: [%d]}}
rules: ['DOMAIN,documentation.example,DIRECT', 'MATCH,REJECT']
`, port))
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	baseline := engine.ResourceAcquireCount()
	plan := engine.Plan("sniffer-http-plan", raw, nil)
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	validation := engine.Validate("sniffer-http-validate", raw, prepared)
	if plan.Category != "planned" || validation.Category != "pass" {
		t.Fatalf("original sniffer must prepare: %s/%s", plan.Code, validation.Code)
	}
	cfg, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { discardUnpublishedPublicSniffer(t, cfg) })
	if received.Load() != 0 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("preparation must not start or contact sniffed destinations")
	}
	var protected atomic.Int32
	_, generation := activatePublicPolicy(t, cfg, []string{"127.0.0.1"}, &protected)
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	client, inbound := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{Type: C.TUN, NetWork: C.TCP, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: 43117, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(port)}
	done := make(chan struct{})
	go func() { defer close(done); bound.HandleTCPConn(inbound, metadata) }()
	t.Cleanup(func() { _ = client.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: documentation.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("request write failed: %v; sniff=%q host=%q", err, metadata.SniffHost, metadata.Host)
	}
	response, err := io.ReadAll(client)
	if err != nil || !containsPublicAnswer(response) || received.Load() != 1 || metadata.SniffHost != "documentation.example" || protected.Load() == 0 {
		t.Fatalf("enabled original sniffer must route the pure-IP request by its declared domain: %v", err)
	}
	_ = client.Close()
	cfg.CancelMobilePolicyServices()
	tunnel.CancelForwarding()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = tunnel.StopForwarding(ctx); err != nil {
		t.Fatal(err)
	}
	if err = cfg.WaitMobilePolicyServices(ctx); err != nil {
		t.Fatal(err)
	}
}

func containsPublicAnswer(data []byte) bool {
	for at := 0; at+len("public-sniff-answer") <= len(data); at++ {
		if string(data[at:at+len("public-sniff-answer")]) == "public-sniff-answer" {
			return true
		}
	}
	return false
}

func TestOriginalSnifferPlansAndUsesOnlyPreparedScopedGeoAndRuleSetMatchers(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	baseline := engine.ResourceAcquireCount()
	raw := []byte(`ipv6: false
dns: {enable: false}
geodata-mode: true
geodata-loader: standard
rule-providers:
 PublicDomains: {type: inline, behavior: domain, payload: ['skipped.example']}
 PublicAddresses: {type: inline, behavior: ipcidr, payload: ['198.51.100.0/24']}
sniffer:
 enable: true
 parse-pure-ip: true
 force-domain: ['geosite:DOC']
 skip-domain: ['rule-set:PublicDomains']
 skip-src-address: ['geoip:DOC']
 skip-dst-address: ['rule-set:PublicAddresses']
 sniff: {HTTP: {ports: [80], override-destination: true}, TLS: {ports: [443]}, QUIC: {ports: [443]}}
rules: ['MATCH,REJECT']
`)
	plan := engine.Plan("sniffer-scoped-plan", raw, nil)
	if plan.Category != "planned" || plan.ResourcesComplete || len(plan.Requirements) != 2 {
		t.Fatalf("original sniffer Geo dependencies must enter fixed resource closure: %s/%s", plan.Category, plan.Code)
	}
	site, _ := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "forced.example"}}}}})
	ip, _ := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "DOC", Cidr: []*router.CIDR{{Ip: netip.MustParseAddr("192.0.2.0").AsSlice(), Prefix: 24}}}}})
	resources := []contract.Resource{}
	for _, req := range plan.Requirements {
		data := site
		if req.Kind == "geoip" {
			data = ip
		}
		resources = append(resources, savePublicResource(t, root, req, data))
	}
	prepared, err := contract.Seal(plan.InputDigest, resources, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("sniffer-scoped-validate", raw, prepared); receipt.Category != "pass" {
		t.Fatalf("scoped original sniffers must validate: %s", receipt.Code)
	}
	cfg, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Discard(context.Background())
	if cfg.Sniffer == nil || !cfg.Sniffer.ForceDomain[0].MatchDomain("forced.example") || !cfg.Sniffer.SkipDomain[0].MatchDomain("skipped.example") || !cfg.Sniffer.SkipSrcAddress[0].MatchIp(netip.MustParseAddr("192.0.2.10")) || !cfg.Sniffer.SkipDstAddress[0].MatchIp(netip.MustParseAddr("198.51.100.10")) {
		t.Fatal("scoped sniffer matchers lost original prepared values")
	}
	if engine.ResourceAcquireCount() != baseline {
		t.Fatal("scoped sniffer planning/construction cannot fetch geodata")
	}
}
