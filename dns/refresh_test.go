package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type refreshTestCache struct {
	dnsCache
	committed chan struct{}
}

func (c *refreshTestCache) SetWithExpire(key string, msg *D.Msg, expire time.Time) {
	c.dnsCache.SetWithExpire(key, msg, expire)
	c.committed <- struct{}{}
}

type refreshTestClient struct {
	entered   chan struct{}
	release   chan struct{}
	failFirst bool
	calls     atomic.Int32
}

func (*refreshTestClient) Address() string  { return "refresh-test" }
func (*refreshTestClient) ResetConnection() {}
func (c *refreshTestClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if c.failFirst {
			return nil, errors.New("first upstream attempt failed")
		}
	}
	return externalAnswer(ctx, q)
}

func newRefreshTestResolver(t *testing.T, failFirst bool) (*Resolver, *refreshTestClient, *refreshTestCache, func()) {
	t.Helper()
	c := &refreshTestClient{entered: make(chan struct{}), release: make(chan struct{}), failFirst: failFirst}
	r := NewResolverFromClient(c)
	cache := &refreshTestCache{dnsCache: r.cache, committed: make(chan struct{}, 8)}
	r.cache = cache
	var once sync.Once
	release := func() { once.Do(func() { close(c.release) }) }
	t.Cleanup(release)
	return r, c, cache, release
}

func TestResolverCancelledWaiterStillFillsCache(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		name := "success"
		if failFirst {
			name = "retry-after-upstream-error"
		}
		t.Run(name, func(t *testing.T) {
			r, client, cache, release := newRefreshTestResolver(t, failFirst)
			q := new(D.Msg).SetQuestion("cancelled-cache.test.", D.TypeA)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := r.ExchangeContext(ctx, q); result <- err }()
			<-client.entered
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("waiter cancellation: %v", err)
			}
			release()
			// Wait for the original worker (or its existing error monitor's
			// retry) to publish, without starting a second lookup to fill cache.
			<-cache.committed
			answer, err := r.ExchangeContext(context.Background(), q)
			if err != nil || answer == nil || len(answer.Answer) != 1 {
				t.Fatalf("cache was not filled after waiter cancellation: %v, %v", answer, err)
			}
			want := int32(1)
			if failFirst {
				want++
			}
			if got := client.calls.Load(); got != want {
				t.Fatalf("upstream calls=%d, want %d", got, want)
			}
		})
	}
}

func TestResolverExpiredCacheStillRefreshes(t *testing.T) {
	r, client, cache, release := newRefreshTestResolver(t, false)
	q := new(D.Msg).SetQuestion("expired-cache.test.", D.TypeA)
	stale, _ := externalAnswer(context.Background(), q)
	stale.Answer[0].(*D.A).A = net.ParseIP("192.0.2.9")
	cache.dnsCache.SetWithExpire(networkQuestionKey(q.Question[0]), stale, time.Now().Add(-time.Second))
	answer, err := r.ExchangeContext(context.Background(), q)
	if err != nil || answer == nil || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "192.0.2.9" {
		t.Fatalf("expired cache answer: %v, %v", answer, err)
	}
	<-client.entered
	release()
	<-cache.committed
	answer, err = r.ExchangeContext(context.Background(), q)
	if err != nil || answer == nil || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "192.0.2.8" {
		t.Fatalf("refreshed cache answer: %v, %v", answer, err)
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("upstream calls=%d, want 1", got)
	}
}
