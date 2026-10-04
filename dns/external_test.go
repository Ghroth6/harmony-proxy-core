package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type externalServiceFunc func(context.Context, *D.Msg) (*D.Msg, error)

func (f externalServiceFunc) ServeMsg(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	return f(ctx, q)
}
func externalAnswer(_ context.Context, q *D.Msg) (*D.Msg, error) {
	r := new(D.Msg).SetReply(q)
	r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.8")}}
	return r, nil
}
func externalTestSetup(t *testing.T) {
	t.Helper()
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := SetExternalIngressManaged(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := StopExternalIngress(ctx); err != nil {
			t.Error(err)
		}
		if err := SetExternalIngressManaged(false); err != nil {
			t.Error(err)
		}
	})
}
func externalFreeAddress(t *testing.T) string {
	t.Helper()
	// Windows may reserve different port ranges for TCP and UDP. A free TCP
	// ephemeral port alone does not prove that UDP may bind the same number.
	// Its UDP allocator can also return hundreds of consecutive ports excluded
	// from TCP, so retry across the range rather than repeat the :0 allocation.
	var bindErrors []error
	for attempt := 0; attempt < 32; attempt++ {
		candidate := "127.0.0.1:0"
		if attempt > 0 {
			candidate = fmt.Sprintf("127.0.0.1:%d", 1024+rand.Intn(65536-1024))
		}
		p, err := net.ListenPacket("udp", candidate)
		if err != nil {
			bindErrors = append(bindErrors, fmt.Errorf("UDP candidate %s: %w", candidate, err))
			continue
		}
		addr := p.LocalAddr().String()
		l, err := net.Listen("tcp", addr)
		_ = p.Close()
		if err != nil {
			bindErrors = append(bindErrors, fmt.Errorf("TCP candidate %s: %w", addr, err))
			continue
		}
		_ = l.Close()
		return addr
	}
	t.Fatalf("could not acquire a port available to both DNS protocols: %v", errors.Join(bindErrors...))
	return ""
}
func externalQuery(t *testing.T, network, addr string) error {
	t.Helper()
	q := new(D.Msg).SetQuestion("external-lifecycle.test.", D.TypeA)
	m, _, err := (&D.Client{Net: network, Timeout: 300 * time.Millisecond}).Exchange(q, addr)
	if err == nil && (m.Rcode != D.RcodeSuccess || len(m.Answer) != 1) {
		return errors.New("missing DNS answer")
	}
	return err
}
func TestExternalIngressRequiresStartAndClosesBothProtocols(t *testing.T) {
	externalTestSetup(t)
	addr := externalFreeAddress(t)
	if err := ReCreateServer(addr, &net.ListenConfig{}, externalServiceFunc(externalAnswer)); err != nil {
		t.Fatal(err)
	}
	if err := externalQuery(t, "tcp", addr); err == nil {
		t.Fatal("configuration opened DNS before Start")
	}
	if err := StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		if err := externalQuery(t, network, addr); err != nil {
			t.Fatalf("%s: %v", network, err)
		}
	}
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("TCP not released: %v", err)
	}
	_ = l.Close()
	p, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("UDP not released: %v", err)
	}
	_ = p.Close()
}
func TestExternalIngressReportsOccupiedBindAndRollsBack(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			externalTestSetup(t)
			addr := externalFreeAddress(t)
			var release func()
			if network == "tcp" {
				l, err := net.Listen(network, addr)
				if err != nil {
					t.Fatal(err)
				}
				release = func() { _ = l.Close() }
			} else {
				p, err := net.ListenPacket(network, addr)
				if err != nil {
					t.Fatal(err)
				}
				release = func() { _ = p.Close() }
			}
			defer release()
			if err := ReCreateServer(addr, &net.ListenConfig{}, externalServiceFunc(externalAnswer)); err != nil {
				t.Fatal(err)
			}
			if err := StartExternalIngress(context.Background()); err == nil || !strings.Contains(err.Error(), "bind DNS") {
				t.Fatalf("bind result: %v", err)
			}
			if external.run != nil {
				t.Fatal("clean rollback retained run")
			}
			release()
			if err := StartExternalIngress(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := externalQuery(t, "udp", addr); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type externalFailPacket struct {
	net.PacketConn
	fail *atomic.Bool
}

func (p *externalFailPacket) Close() error {
	err := p.PacketConn.Close()
	if p.fail.Load() {
		return errors.New("injected UDP close failure")
	}
	return err
}

type externalFailListenConfig struct {
	net.ListenConfig
	fail *atomic.Bool
}

func (l *externalFailListenConfig) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	p, err := l.ListenConfig.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &externalFailPacket{p, l.fail}, nil
}
func TestExternalIngressRetainsPartialBindCloseFailure(t *testing.T) {
	externalTestSetup(t)
	occupied, err := net.Listen("tcp", externalFreeAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	fail := &atomic.Bool{}
	fail.Store(true)
	if err := ReCreateServer(occupied.Addr().String(), &externalFailListenConfig{fail: fail}, externalServiceFunc(externalAnswer)); err != nil {
		t.Fatal(err)
	}
	err = StartExternalIngress(context.Background())
	if err == nil || !strings.Contains(err.Error(), "injected UDP close failure") {
		t.Fatalf("lost rollback error: %v", err)
	}
	if external.run == nil {
		t.Fatal("failed cleanup lost resource record")
	}
	if err := StartExternalIngress(context.Background()); err == nil {
		t.Fatal("started over failed cleanup")
	}
	fail.Store(false)
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = occupied.Close()
	if err := StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestExternalIngressRetainsStopCloseFailure(t *testing.T) {
	externalTestSetup(t)
	fail := &atomic.Bool{}
	if err := ReCreateServer(externalFreeAddress(t), &externalFailListenConfig{fail: fail}, externalServiceFunc(externalAnswer)); err != nil {
		t.Fatal(err)
	}
	if err := StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := StopExternalIngress(context.Background()); err == nil || !strings.Contains(err.Error(), "injected UDP close failure") {
		t.Fatalf("lost close error: %v", err)
	}
	if err := StartExternalIngress(context.Background()); err == nil {
		t.Fatal("started over failed stop")
	}
	fail.Store(false)
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestExternalIngressWaitsForLateHandlerAndRejectsStaleReply(t *testing.T) {
	externalTestSetup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	service := externalServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		once.Do(func() { close(entered); <-release })
		return externalAnswer(ctx, q)
	})
	addr := externalFreeAddress(t)
	if err := ReCreateServer(addr, &net.ListenConfig{}, service); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if err := StartExternalIngress(runCtx); err != nil {
		t.Fatal(err)
	}
	queryDone := make(chan error, 1)
	go func() { queryDone <- externalQuery(t, "udp", addr) }()
	<-entered
	cancelRun()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := StopExternalIngress(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop did not retain pending handler: %v", err)
	}
	if err := StartExternalIngress(context.Background()); err == nil {
		t.Fatal("overlapped generations")
	}
	close(release)
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-queryDone; err == nil {
		t.Fatal("retired handler sent successful reply")
	}
	if err := StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := externalQuery(t, "udp", addr); err != nil {
		t.Fatal(err)
	}
}

type externalSharedClient struct {
	entered   chan struct{}
	release   chan struct{}
	calls     atomic.Int64
	cancelled atomic.Bool
}

func (c *externalSharedClient) Address() string  { return "shared-test" }
func (c *externalSharedClient) ResetConnection() {}
func (c *externalSharedClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	select {
	case <-c.release:
		return externalAnswer(ctx, q)
	case <-ctx.Done():
		c.cancelled.Store(true)
		return nil, ctx.Err()
	}
}
func TestExternalIngressCancellationPreservesSharedManagementResolver(t *testing.T) {
	externalTestSetup(t)
	client := &externalSharedClient{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewResolverFromClient(client)
	s := NewService(r, NewEnhancer(EnhancerConfig{}))
	addr := externalFreeAddress(t)
	if err := ReCreateServer(addr, &net.ListenConfig{}, s); err != nil {
		t.Fatal(err)
	}
	if err := StartExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	externalDone := make(chan error, 1)
	go func() { externalDone <- externalQuery(t, "udp", addr) }()
	<-client.entered
	// A management request uses the same resolver and question while the
	// upstream query is still in flight; external Stop must not kill it.
	managementDone := make(chan error, 1)
	go func() {
		_, err := r.ExchangeContext(context.Background(), new(D.Msg).SetQuestion("external-lifecycle.test.", D.TypeA))
		managementDone <- err
	}()
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.cancelled.Load() {
		t.Fatal("external cancellation cancelled shared upstream query")
	}
	close(client.release)
	if err := <-managementDone; err != nil {
		t.Fatalf("management query failed: %v", err)
	}
	if err := <-externalDone; err == nil {
		t.Fatal("cancelled external request succeeded")
	}
	if client.calls.Load() != 1 {
		t.Fatalf("shared query duplicated: %d", client.calls.Load())
	}
	if _, err := s.ServeMsg(context.Background(), new(D.Msg).SetQuestion("external-lifecycle.test.", D.TypeA)); err != nil {
		t.Fatalf("internal service disabled by Stop: %v", err)
	}
}
func TestExternalIngressDefaultConfigStartsAutomatically(t *testing.T) {
	if err := SetExternalIngressManaged(false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = StopExternalIngress(context.Background()) })
	addr := externalFreeAddress(t)
	if err := ReCreateServer(addr, &net.ListenConfig{}, externalServiceFunc(externalAnswer)); err != nil {
		t.Fatal(err)
	}
	if err := externalQuery(t, "udp", addr); err != nil {
		t.Fatal(err)
	}
}

type externalPendingListenConfig struct {
	net.ListenConfig
	entered chan struct{}
}

func (l *externalPendingListenConfig) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	close(l.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestExternalIngressStopCancelsPendingBindBeforeOperationLock(t *testing.T) {
	externalTestSetup(t)
	lc := &externalPendingListenConfig{entered: make(chan struct{})}
	addr := externalFreeAddress(t)
	if err := ReCreateServer(addr, lc, externalServiceFunc(externalAnswer)); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- StartExternalIngress(context.Background()) }()
	select {
	case <-lc.entered:
	case err := <-started:
		t.Fatalf("Start failed before pending bind: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Start did not reach pending bind")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := StopExternalIngress(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending Start result: %v", err)
	}
	if external.run != nil {
		t.Fatal("cancelled Start left run")
	}
	p, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("partial UDP bind retained: %v", err)
	}
	_ = p.Close()
}

func TestExternalIngressPreparedSocketsDoNotServeBeforeActivation(t *testing.T) {
	externalTestSetup(t)
	addr := externalFreeAddress(t)
	var queries atomic.Int64
	service := externalServiceFunc(func(ctx context.Context, q *D.Msg) (*D.Msg, error) { queries.Add(1); return externalAnswer(ctx, q) })
	if err := ReCreateServer(addr, &net.ListenConfig{}, service); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := PrepareExternalIngress(ctx); err != nil {
		t.Fatal(err)
	}
	// The port is genuinely bound, but the data service is still closed.
	if l, err := net.Listen("tcp", addr); err == nil {
		_ = l.Close()
		t.Fatal("Prepare did not bind TCP")
	}
	if err := externalQuery(t, "udp", addr); err == nil {
		t.Fatal("prepared UDP served a query")
	}
	if err := externalQuery(t, "tcp", addr); err == nil {
		t.Fatal("prepared TCP served a query")
	}
	if queries.Load() != 0 {
		t.Fatal("prepared ingress invoked resolver")
	}
	if err := ActivateExternalIngress(); err != nil {
		t.Fatal(err)
	}
	if err := externalQuery(t, "udp", addr); err != nil {
		t.Fatal(err)
	}
	if queries.Load() != 1 {
		t.Fatal("activation did not admit query")
	}
	if err := StopExternalIngress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := PrepareExternalIngress(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := ActivateExternalIngress(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Prepare activated: %v", err)
	}
}
