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

func TestScopedRootDNSQuestionKeepsLegacyAAndAAAAAnswersWithoutStateFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	state, err := fakeip.NewScopedPersistence(root, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatal(err)
	}
	var failures atomic.Int32
	state.SetFailureHandler(func() { failures.Add(1) })
	newService := func(persistent bool) (*dns.Service, *dns.ResolverEnhancer) {
		var store *fakeip.ScopedPersistence
		if persistent {
			store = state
		}
		v4, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Persistence: persistent, ScopedPersistence: store})
		if err != nil {
			t.Fatal(err)
		}
		v6, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("fdfe:dcba:9876::1/64"), Persistence: persistent, ScopedPersistence: store})
		if err != nil {
			t.Fatal(err)
		}
		resolvers := dns.NewResolver(dns.Config{IPv6: true})
		mapper := dns.NewEnhancer(dns.EnhancerConfig{IPv6: true, EnhancedMode: C.DNSFakeIP, FakeIPPool: v4, FakeIPPool6: v6, FakeIPSkipper: &fakeip.Skipper{}})
		return dns.NewService(resolvers, mapper), mapper
	}
	legacy, _ := newService(false)
	scoped, mapper := newService(true)
	if err = state.Activate(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	}()
	expected := map[uint16]string{}
	checkRoot := func(service *dns.Service, mapper *dns.ResolverEnhancer, kind uint16) {
		t.Helper()
		query := new(D.Msg)
		query.SetQuestion(".", kind)
		actual, actualErr := service.ServeMsg(context.Background(), query)
		if actualErr != nil || actual == nil || len(actual.Answer) != 1 {
			t.Errorf("legal root question must retain the original fake-IP answer: kind=%d err=%v", kind, actualErr)
			return
		}
		if actual.Answer[0].String() != expected[kind] {
			t.Error("root question answer changed")
		}
		var address netip.Addr
		switch answer := actual.Answer[0].(type) {
		case *D.A:
			address, _ = netip.AddrFromSlice(answer.A)
		case *D.AAAA:
			address, _ = netip.AddrFromSlice(answer.AAAA)
		}
		if host, ok := mapper.FindHostByIP(address.Unmap()); !ok || host != "" {
			t.Error("root mapping must remain present and distinguishable from a missing mapping")
		}
	}
	for _, kind := range []uint16{D.TypeA, D.TypeAAAA} {
		query := new(D.Msg)
		query.SetQuestion(".", kind)
		original, originalErr := legacy.ServeMsg(context.Background(), query)
		if originalErr != nil || original == nil || len(original.Answer) != 1 {
			t.Fatal("legacy legal root question baseline is invalid", originalErr)
		}
		expected[kind] = original.Answer[0].String()
		checkRoot(scoped, mapper, kind)
	}
	if failures.Load() != 0 || state.Error() != nil {
		t.Fatal("a legal DNS input must not become a sticky persistence failure")
	}
	query := new(D.Msg)
	query.SetQuestion("documentation-after-root.example.", D.TypeA)
	reply, err := scoped.ServeMsg(context.Background(), query)
	if err != nil || reply == nil || len(reply.Answer) != 1 {
		t.Fatal("root question withdrew later DNS admission", err)
	}
	normalAnswer := reply.Answer[0].String()
	for cycle := 0; cycle < 2; cycle++ {
		if err = state.Close(); err != nil {
			t.Fatal(err)
		}
		state, err = fakeip.NewScopedPersistence(root, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
		if err != nil {
			t.Fatal(err)
		}
		state.SetFailureHandler(func() { failures.Add(1) })
		scoped, mapper = newService(true)
		if err = state.Activate(); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []uint16{D.TypeA, D.TypeAAAA} {
			checkRoot(scoped, mapper, kind)
		}
		if reply, err = scoped.ServeMsg(context.Background(), query); err != nil || reply == nil || len(reply.Answer) != 1 || reply.Answer[0].String() != normalAnswer {
			t.Fatal("root mapping must not collide with a normal host across reopening", err)
		}
		if failures.Load() != 0 || state.Error() != nil {
			t.Fatal("reopening a root mapping must not create a sticky persistence failure")
		}
	}
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
