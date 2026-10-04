package route

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

type dohServiceFunc func(context.Context, *D.Msg) (*D.Msg, error)

func (f dohServiceFunc) ServeMsg(ctx context.Context, q *D.Msg) (*D.Msg, error) { return f(ctx, q) }
func dohAnswer(_ context.Context, q *D.Msg) (*D.Msg, error) {
	r := new(D.Msg).SetReply(q)
	r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.17")}}
	return r, nil
}
func dohLifecycleSetup(t *testing.T, service resolver.Service) *httptest.Server {
	t.Helper()
	if err := dns.StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dns.SetExternalIngressManaged(true); err != nil {
		t.Fatal(err)
	}
	if err := dns.ReCreateServer("", nil, service); err != nil {
		t.Fatal(err)
	}
	oldResolver, oldService := resolver.DefaultResolver, resolver.DefaultService
	resolver.DefaultResolver = dns.NewResolver(dns.Config{}).Resolver
	resolver.DefaultService = service
	server := httptest.NewServer(router(false, "", "/dns-query", Cors{}))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := dns.StopExternalIngress(ctx); err != nil {
			t.Error(err)
		}
		server.Close()
		resolver.DefaultResolver, resolver.DefaultService = oldResolver, oldService
		if err := dns.SetExternalIngressManaged(false); err != nil {
			t.Error(err)
		}
	})
	return server
}
func dohURL(server *httptest.Server) string {
	q := new(D.Msg).SetQuestion("doh-lifecycle.test.", D.TypeA)
	b, _ := q.Pack()
	return server.URL + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(b)
}
func dohGetStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := (&http.Client{Timeout: time.Second}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
func TestDoHLifecycleKeepsManagementControllerAvailable(t *testing.T) {
	s := dohLifecycleSetup(t, dohServiceFunc(dohAnswer))
	if status := dohGetStatus(t, dohURL(s)); status != http.StatusServiceUnavailable {
		t.Fatalf("DoH before Start: %d", status)
	}
	if status := dohGetStatus(t, s.URL+"/version"); status != http.StatusOK {
		t.Fatalf("management before Start: %d", status)
	}
	if err := dns.StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := dohGetStatus(t, dohURL(s)); status != http.StatusOK {
		t.Fatalf("DoH running: %d", status)
	}
	if err := dns.StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := dohGetStatus(t, dohURL(s)); status != http.StatusServiceUnavailable {
		t.Fatalf("DoH after Stop: %d", status)
	}
	if status := dohGetStatus(t, s.URL+"/version"); status != http.StatusOK {
		t.Fatalf("management after Stop: %d", status)
	}
	if _, err := resolver.ServeMsg(context.Background(), new(D.Msg).SetQuestion("management.test.", D.TypeA)); err != nil {
		t.Fatal(err)
	}
}
func TestDoHLifecycleParentCancellationEndsInflightQuery(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := dohLifecycleSetup(t, dohServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := dns.StartExternalIngress(ctx); err != nil {
		t.Fatal(err)
	}
	status := make(chan int, 1)
	go func() { status <- dohGetStatus(t, dohURL(s)) }()
	<-entered
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach DoH")
	}
	if got := <-status; got != http.StatusServiceUnavailable {
		t.Fatalf("cancelled DoH returned %d", got)
	}
	if got := dohGetStatus(t, dohURL(s)); got != http.StatusServiceUnavailable {
		t.Fatalf("cancelled parent admitted new query: %d", got)
	}
	if err := dns.StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dohGetStatus(t, s.URL+"/version"); got != http.StatusOK {
		t.Fatal(got)
	}
}
func TestDoHLifecycleRetainsPendingHandlerAndSuppressesLateSuccess(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := dohLifecycleSetup(t, dohServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		once.Do(func() { close(entered); <-release })
		return dohAnswer(ctx, q)
	}))
	if err := dns.StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := make(chan int, 1)
	go func() { status <- dohGetStatus(t, dohURL(s)) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := dns.StopExternalIngress(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost pending query: %v", err)
	}
	if err := dns.StartExternalIngress(context.Background()); err == nil {
		t.Fatal("started over pending query")
	}
	close(release)
	if got := <-status; got != http.StatusServiceUnavailable {
		t.Fatalf("late query returned success: %d", got)
	}
	if err := dns.StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dns.StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dohGetStatus(t, dohURL(s)); got != http.StatusOK {
		t.Fatal(got)
	}
}
func TestDoHLifecycleUnmanagedDefaultRemainsAvailable(t *testing.T) {
	s := dohLifecycleSetup(t, dohServiceFunc(dohAnswer))
	if err := dns.SetExternalIngressManaged(false); err != nil {
		t.Fatal(err)
	}
	if got := dohGetStatus(t, dohURL(s)); got != http.StatusOK {
		t.Fatal(got)
	}
}

func TestDoHLifecycleStopInterruptsIncompletePOSTBody(t *testing.T) {
	s := dohLifecycleSetup(t, dohServiceFunc(dohAnswer))
	if err := dns.StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The peer promises a body but never finishes it. Expect/100-continue is
	// the synchronization point proving the handler is actually reading it.
	_, err = fmt.Fprintf(conn, "POST /dns-query HTTP/1.1\r\nHost: test\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	if _, err = conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dns.StopExternalIngress(ctx); err != nil {
		t.Fatalf("Stop left POST body pending: %v", err)
	}
	if got := dohGetStatus(t, s.URL+"/version"); got != http.StatusOK {
		t.Fatal(got)
	}
}

func TestDoHLifecyclePreparedRunRejectsQueriesUntilActivation(t *testing.T) {
	s := dohLifecycleSetup(t, dohServiceFunc(dohAnswer))
	if err := dns.PrepareExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dohGetStatus(t, dohURL(s)); got != http.StatusServiceUnavailable {
		t.Fatalf("prepared DoH response: %d", got)
	}
	if got := dohGetStatus(t, s.URL+"/version"); got != http.StatusOK {
		t.Fatal(got)
	}
	if err := dns.ActivateExternalIngress(); err != nil {
		t.Fatal(err)
	}
	if got := dohGetStatus(t, dohURL(s)); got != http.StatusOK {
		t.Fatal(got)
	}
}
