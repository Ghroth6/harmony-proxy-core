package fakeip_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

// This is the real filesystem boundary. No DB transaction, DNS service or
// fake-IP mapping is replaced. Closing this actual file injects an OS failure.
type capturedStateFiles struct {
	*os.Root
	file *os.File
}

func (f *capturedStateFiles) OpenFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	file, err := f.Root.OpenFile(name, flags, mode)
	f.file = file
	return file, err
}

func TestScopedStateWriteFailureReturnsNoDNSAnswerAndRetainsActualCloseFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files := &capturedStateFiles{Root: root}
	state, err := fakeip.NewScopedPersistence(files, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Persistence: true, ScopedPersistence: state})
	if err != nil {
		t.Fatal(err)
	}
	owner := dns.NewResolverOwner()
	resolvers := dns.NewResolver(dns.Config{Owner: owner})
	mapper := dns.NewEnhancer(dns.EnhancerConfig{EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, FakeIPSkipper: &fakeip.Skipper{}})
	service := dns.NewService(resolvers, mapper)
	var failures atomic.Int32
	state.SetFailureHandler(func() { failures.Add(1); owner.Cancel(); state.Cancel() })
	if err = state.Activate(); err != nil {
		t.Fatal(err)
	}
	if err = owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	message := new(D.Msg)
	message.SetQuestion("documentation-before.example.", D.TypeA)
	if answer, err := service.ServeMsg(context.Background(), message); err != nil || len(answer.Answer) != 1 {
		t.Fatal("actual persisted DNS answer must work before the file fault", err)
	}
	if err = files.file.Close(); err != nil {
		t.Fatal(err)
	}
	message.SetQuestion("documentation-failed.example.", D.TypeA)
	answer, err := service.ServeMsg(context.Background(), message)
	if !errors.Is(err, fakeip.ErrStateFailed) || answer != nil || failures.Load() != 1 || state.Error() == nil {
		t.Fatalf("failed synchronous commit must return no DNS success: answer=%v err=%v failures=%d", answer != nil, err, failures.Load())
	}
	if answer, err = service.ServeMsg(context.Background(), message); err == nil || answer != nil {
		t.Fatal("sticky failure must close later request admission")
	}
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = owner.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if err = state.Wait(wait); !errors.Is(err, fakeip.ErrStateClose) {
		t.Fatal("actual DB Sync/Close errors must remain owned", err)
	}
	if err = state.Wait(wait); !errors.Is(err, fakeip.ErrStateClose) {
		t.Fatal("a second Wait must not replace failed Close with idempotent success", err)
	}
	if _, err = files.file.Stat(); err == nil || files.file.Fd() != ^uintptr(0) {
		t.Fatal("fault injected into the real file must be read back", err)
	}
}

func TestScopedPoolsKeepIndependentOffsetsFlushAndRawIdentity(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	state, _ := fakeip.NewScopedPersistence(root, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/29"), Persistence: true, ScopedPersistence: state})
	if err != nil {
		t.Fatal(err)
	}
	v6, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("fdfe:dcba:9876::/125"), Persistence: true, ScopedPersistence: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.LookupWithError("documentation.example"); !errors.Is(err, fakeip.ErrStateInactive) {
		t.Fatal("pure prepared pool must not silently open a database")
	}
	if err = state.Activate(); err != nil {
		t.Fatal(err)
	}
	first, err := pool.LookupWithError("documentation.example")
	if err != nil {
		t.Fatal(err)
	}
	first6, err := v6.LookupWithError("documentation.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"documentation-b.example", "documentation-c.example", "documentation-d.example"} {
		if _, err = pool.LookupWithError(host); err != nil {
			t.Fatal(err)
		}
	}
	if host, ok := pool.LookBack(first); !ok || host != "documentation-d.example" {
		t.Fatal("original cyclic allocation must atomically replace both mapping directions")
	}
	if host, ok := v6.LookBack(first6); !ok || host != "documentation.example" {
		t.Fatal("IPv4 cycling must not alter the IPv6 pool")
	}
	if err = pool.FlushFakeIP(); err != nil {
		t.Fatal(err)
	}
	if !v6.Exist(first6) || pool.Exist(first) {
		t.Fatal("scoped flush must affect only its own prefix bucket")
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	other, _ := fakeip.NewScopedPersistence(root, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	otherPool, err := fakeip.New(fakeip.Options{IPNet: v6.IPNet(), Persistence: true, ScopedPersistence: other})
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Activate(); err != nil {
		t.Fatal(err)
	}
	if otherPool.Exist(first6) {
		t.Fatal("a different raw identity must not inherit another policy's mappings")
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
}
