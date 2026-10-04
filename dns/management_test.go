package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	D "github.com/miekg/dns"
)

type managementLateDNSClient struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (*managementLateDNSClient) Address() string  { return "late-network-test" }
func (*managementLateDNSClient) ResetConnection() {}
func (c *managementLateDNSClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		<-c.release
	}
	return externalAnswer(ctx, q)
}

func TestManagementNetworkWaitsSharedDNSAndRejectsLateCache(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	c := &managementLateDNSClient{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewResolverFromClient(c)
	query := new(D.Msg).SetQuestion("network-epoch.test.", D.TypeA)
	result := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(context.Background(), query); result <- err }()
	<-c.entered
	forwarding.CancelManagementNetwork()
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := forwarding.WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost DNS worker: %v", err)
	}
	close(c.release)
	if err := <-result; err == nil {
		t.Fatal("late reply accepted")
	}
	if err := forwarding.WaitManagementNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 2 {
		t.Fatalf("old answer cached or new query lost: %d", c.calls.Load())
	}
}

func TestManagementNetworkSharedDNSOutlivesIndividualWaiter(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	c := &externalSharedClient{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewResolverFromClient(c)
	query := new(D.Msg).SetQuestion("shared-epoch.test.", D.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(ctx, query); result <- err }()
	<-c.entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if c.cancelled.Load() {
		t.Fatal("individual waiter canceled shared query")
	}
	close(c.release)
	if _, err := r.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 1 {
		t.Fatalf("duplicated shared request: %d", c.calls.Load())
	}
}
