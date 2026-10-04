package configresources

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type ownedAdapter struct {
	C.ProxyAdapter
	closed  atomic.Int32
	closeFn func() error
}

func (a *ownedAdapter) Name() string { return "owned" }
func (a *ownedAdapter) Close() error {
	a.closed.Add(1)
	if a.closeFn != nil {
		return a.closeFn()
	}
	return nil
}

type ownedProxy struct {
	C.Proxy
	adapter C.ProxyAdapter
}

func (p *ownedProxy) Adapter() C.ProxyAdapter { return p.adapter }
func (p *ownedProxy) Name() string            { return p.adapter.Name() }

type ownedProvider struct {
	P.Provider
	cancelled chan struct{}
	other     *ownedProvider
	fail      error
}

func (p *ownedProvider) Name() string { return "provider" }
func (p *ownedProvider) Cancel()      { close(p.cancelled) }
func (p *ownedProvider) Wait(ctx context.Context) error {
	if p.other != nil {
		select {
		case <-p.other.cancelled:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.fail
}

func TestCandidateCleanupDeduplicatesAdaptersAndCancelsAllBeforeWaiting(t *testing.T) {
	a := &ownedAdapter{}
	p1 := &ownedProvider{cancelled: make(chan struct{})}
	p2 := &ownedProvider{cancelled: make(chan struct{})}
	p1.other, p2.other = p2, p1
	var set Set
	set.AddProxy(&ownedProxy{adapter: a})
	set.AddProxy(&ownedProxy{adapter: a})
	set.AddAdapter(a)
	set.AddProvider(p1)
	set.AddProvider(p1)
	set.AddProvider(p2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := set.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := a.closed.Load(); got != 1 {
		t.Fatalf("Close count = %d, want 1", got)
	}
}

func TestCandidateCleanupTimeoutRetainsActualClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a := &ownedAdapter{closeFn: func() error { close(entered); <-release; return nil }}
	var set Set
	set.AddAdapter(a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := set.Close(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v", err)
	}
	<-entered
	parseErr := errors.New("original parse failure")
	combined := errors.Join(parseErr, err, err)
	if !errors.Is(combined, parseErr) {
		t.Fatal("lost parse error")
	}
	close(release)
	wait, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := WaitCleanup(wait, combined); err != nil {
		t.Fatal(err)
	}
	if got := a.closed.Load(); got != 1 {
		t.Fatalf("Close count = %d", got)
	}
}

func TestCandidateCleanupReportsAllCloseFailuresAndNeverRetriesThem(t *testing.T) {
	err1, err2 := errors.New("close one"), errors.New("close two")
	a := &ownedAdapter{closeFn: func() error { return err1 }}
	b := &ownedAdapter{closeFn: func() error { return err2 }}
	var set Set
	set.AddAdapter(a)
	set.AddAdapter(b)
	err := set.Close(context.Background())
	if !errors.Is(err, err1) || !errors.Is(err, err2) {
		t.Fatalf("Close = %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := WaitCleanup(context.Background(), err); !errors.Is(err, err1) || !errors.Is(err, err2) {
			t.Fatalf("Wait = %v", err)
		}
	}
	if a.closed.Load() != 1 || b.closed.Load() != 1 {
		t.Fatal("failed Close was retried")
	}
}

func TestCandidateCleanupDoesNotCloseAdaptersWhileTasksCannotFinish(t *testing.T) {
	failure := errors.New("task could not finish")
	p := &ownedProvider{cancelled: make(chan struct{}), fail: failure}
	a := &ownedAdapter{}
	var set Set
	set.AddProvider(p)
	set.AddAdapter(a)
	if err := set.Close(context.Background()); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if a.closed.Load() != 0 {
		t.Fatal("adapter closed while task still owns it")
	}
}

func TestWaitCleanupOmitsOrdinaryParseErrors(t *testing.T) {
	if err := WaitCleanup(context.Background(), errors.New("invalid config")); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateTransferDropsReferencesAndCannotBeDiscarded(t *testing.T) {
	a := &ownedAdapter{}
	p := &ownedProvider{cancelled: make(chan struct{})}
	var set Set
	set.AddAdapter(a)
	set.AddProvider(p)
	if err := set.CheckTransfer(); err != nil {
		t.Fatal(err)
	}
	if err := set.Transfer(); err != nil {
		t.Fatal(err)
	}
	if err := set.Transfer(); err != nil {
		t.Fatal(err)
	}
	if set.adapters != nil || set.proxies != nil || set.providers != nil {
		t.Fatal("candidate retained runtime objects")
	}
	if err := set.Close(context.Background()); !errors.Is(err, ErrTransferred) {
		t.Fatal(err)
	}
	select {
	case <-p.cancelled:
		t.Fatal("transferred provider cancelled")
	default:
	}
	if a.closed.Load() != 0 {
		t.Fatal("transferred adapter closed")
	}
}

func TestDiscardedCandidateCannotTransfer(t *testing.T) {
	var set Set
	if err := set.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := set.CheckTransfer(); !errors.Is(err, ErrCleanupStarted) {
		t.Fatal(err)
	}
	if err := set.Transfer(); !errors.Is(err, ErrCleanupStarted) {
		t.Fatal(err)
	}
}
