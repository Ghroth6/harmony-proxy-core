package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

type forbiddenFallback struct{ calls atomic.Int64 }

func (f *forbiddenFallback) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	f.calls.Add(1)
	return nil, errors.New("fallback called")
}
func (*forbiddenFallback) Address() string  { return "forbidden-fallback" }
func (*forbiddenFallback) ResetConnection() {}

func localDNSServer(t *testing.T, answer string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{PacketConn: conn, Handler: D.HandlerFunc(func(writer D.ResponseWriter, query *D.Msg) {
		response := new(D.Msg)
		response.SetReply(query)
		response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP(answer)}}
		_ = writer.WriteMsg(response)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown(); _ = conn.Close() })
	return conn.LocalAddr().String()
}

func TestPlatformDNSAllClientsFollowNetworkAndOfflineNeverFallsBack(t *testing.T) {
	first := localDNSServer(t, "192.0.2.1")
	second := localDNSServer(t, "192.0.2.2")
	snapshot := platformnetwork.Snapshot{Generation: 1, Online: true, NetworkID: 11, DNS: []string{first}, Interfaces: []platformnetwork.Interface{{Name: "synthetic", Up: true}}}
	if err := platformnetwork.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	client := newSystemClient()
	fallback := &forbiddenFallback{}
	client.defaultNS = []dnsClient{fallback}
	configured := NewResolver(Config{Main: []NameServer{{Net: "system"}}})
	query := new(D.Msg)
	query.SetQuestion("network-change.test.", D.TypeA)
	assertAnswer := func(exchange interface {
		ExchangeContext(context.Context, *D.Msg) (*D.Msg, error)
	}, want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		response, err := exchange.ExchangeContext(ctx, query.Copy())
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Answer) != 1 || response.Answer[0].(*D.A).A.String() != want {
			t.Fatalf("want %s, got %v", want, response)
		}
	}
	assertAnswer(client, "192.0.2.1")
	assertAnswer(configured, "192.0.2.1")
	assertAnswer(resolver.SystemResolver, "192.0.2.1")
	snapshot.Generation, snapshot.NetworkID, snapshot.DNS = 2, 12, []string{second}
	if err := platformnetwork.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	// Same question and long TTL: an earlier network's resolver cache must not win.
	assertAnswer(client, "192.0.2.2")
	assertAnswer(configured, "192.0.2.2")
	assertAnswer(resolver.SystemResolver, "192.0.2.2")
	bad := snapshot
	bad.Generation, bad.DNS = 3, []string{"not-an-IP"}
	if err := platformnetwork.Publish(bad); err == nil {
		t.Fatal("accepted bad DNS")
	}
	assertAnswer(client, "192.0.2.2")
	if err := platformnetwork.Publish(platformnetwork.Snapshot{Generation: 3}); err != nil {
		t.Fatal(err)
	}
	for name, exchange := range map[string]interface {
		ExchangeContext(context.Context, *D.Msg) (*D.Msg, error)
	}{"direct": client, "configured": configured, "global": resolver.SystemResolver} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := exchange.ExchangeContext(ctx, query.Copy())
		cancel()
		if err == nil {
			t.Fatalf("%s retained cached online answer", name)
		}
	}
	if fallback.calls.Load() != 0 || strings.Contains(client.Address(), "defaultNS") {
		t.Fatal("offline fell back to public DNS")
	}
	if _, err := client.getDnsClients(); !errors.Is(err, ErrNoSystemDNS) {
		t.Fatalf("missing explicit offline error: %v", err)
	}
}

type delayedNetworkClient struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (c *delayedNetworkClient) ExchangeContext(ctx context.Context, query *D.Msg) (*D.Msg, error) {
	answer := "192.0.2.2"
	if c.calls.Add(1) == 1 {
		close(c.started)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		answer = "192.0.2.1"
	}
	response := new(D.Msg)
	response.SetReply(query)
	response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP(answer)}}
	return response, nil
}
func (*delayedNetworkClient) Address() string  { return "delayed-network" }
func (*delayedNetworkClient) ResetConnection() {}

func TestNetworkGenerationSeparatesInflightCacheWrites(t *testing.T) {
	client := &delayedNetworkClient{started: make(chan struct{}), release: make(chan struct{})}
	r := &Resolver{main: []dnsClient{client}, cache: Config{}.newCache()}
	query := new(D.Msg)
	query.SetQuestion("inflight.test.", D.TypeA)
	oldResponse := make(chan *D.Msg, 1)
	go func() { response, _ := r.ExchangeContext(context.Background(), query.Copy()); oldResponse <- response }()
	<-client.started
	generation, _ := platformnetwork.Generation()
	if err := platformnetwork.Publish(platformnetwork.Snapshot{Generation: generation + 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := r.ExchangeContext(ctx, query.Copy())
	close(client.release)
	if err != nil || response.Answer[0].(*D.A).A.String() != "192.0.2.2" {
		t.Fatalf("new generation joined old in-flight request: %v %v", response, err)
	}
	if response := <-oldResponse; response == nil || response.Answer[0].(*D.A).A.String() != "192.0.2.1" {
		t.Fatalf("old response: %v", response)
	}
	response, err = r.ExchangeContext(ctx, query.Copy())
	if err != nil || response.Answer[0].(*D.A).A.String() != "192.0.2.2" || client.calls.Load() != 2 {
		t.Fatalf("old completion polluted current cache: %v %v calls=%d", response, err, client.calls.Load())
	}
}
