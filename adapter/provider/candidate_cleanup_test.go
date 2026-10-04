package provider

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

func anyTLSCandidate(name string) map[string]any {
	return map[string]any{"name": name, "type": "anytls", "server": "127.0.0.1", "port": 443, "password": "test-only"}
}

func candidateParser(t *testing.T) resource.Parser[[]C.Proxy] {
	t.Helper()
	parser, err := NewProxiesParser("candidate", nil, "", "", "", "", overrideSchema{}, "")
	if err != nil {
		t.Fatal(err)
	}
	return parser
}

func candidatePayload(t *testing.T, proxies ...map[string]any) []byte {
	t.Helper()
	data, err := yaml.Marshal(ProxySchema{Proxies: proxies})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func anyTLSRoutines() int {
	buffer := make([]byte, 2<<20)
	n := runtime.Stack(buffer, true)
	return strings.Count(string(buffer[:n]), "transport/anytls/util.StartRoutine.func1()")
}

func assertCandidateRoutines(t *testing.T, want int) {
	t.Helper()
	if got := anyTLSRoutines(); got != want {
		t.Fatalf("AnyTLS routines = %d, want %d after synchronous candidate cleanup", got, want)
	}
}

func assertCandidateOpen(t *testing.T, proxy C.Proxy) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := proxy.DialContext(ctx, &C.Metadata{Host: "test.invalid", DstPort: 443})
	if errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, context.Canceled) {
		t.Fatalf("previous adapter no longer accepts a dial: %v", err)
	}
}

func TestProviderParserClosesPartialRealCandidates(t *testing.T) {
	parser := candidateParser(t)
	before := anyTLSRoutines()
	// The first complete adapter starts a real idle-session goroutine. A later
	// adapter failure must close it before this parser returns, without GC.
	_, err := parser(candidatePayload(t, anyTLSCandidate("first"), map[string]any{"name": "bad", "type": "unsupported"}))
	if err == nil || !strings.Contains(err.Error(), "proxy 1 error") {
		t.Fatalf("lost original parse error: %v", err)
	}
	assertCandidateRoutines(t, before)
}

func TestProviderConstructorsCancelFailedHealthOwner(t *testing.T) {
	for _, kind := range []string{"inline", "set", "compatible"} {
		t.Run(kind, func(t *testing.T) {
			hc := NewHealthCheck(nil, "http://test.invalid", 100, 1, false, nil)
			before := anyTLSRoutines()
			payload := []map[string]any{anyTLSCandidate("first"), {"name": "bad", "type": "unsupported"}}
			var err error
			switch kind {
			case "inline":
				_, err = NewInlineProvider("inline", payload, candidateParser(t), hc)
			case "set":
				_, err = NewProxySetProvider("set", 0, payload, candidateParser(t), resource.NewFileVehicle(t.TempDir()), hc)
			case "compatible":
				_, err = NewCompatibleProvider("compatible", nil, hc)
			}
			if err == nil || !errors.Is(hc.ctx.Err(), context.Canceled) {
				t.Fatalf("failed constructor retained health owner: constructor=%v health=%v", err, hc.ctx.Err())
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := hc.wait(ctx); err != nil {
				t.Fatal(err)
			}
			assertCandidateRoutines(t, before)
		})
	}
}

func TestProviderWriteFailureDiscardsRealCandidateAndKeepsCurrent(t *testing.T) {
	parser := candidateParser(t)
	hc := NewHealthCheck(nil, "", 0, 0, false, nil)
	// Writing a provider file over an existing directory fails on every host.
	pd, err := NewProxySetProvider("current", 0, []map[string]any{anyTLSCandidate("current")}, parser, resource.NewFileVehicle(t.TempDir()), hc)
	if err != nil {
		t.Fatal(err)
	}
	current := pd.Proxies()[0]
	defer current.Close()
	defer pd.Close()
	before := anyTLSRoutines()
	_, _, err = pd.SideUpdate(candidatePayload(t, anyTLSCandidate("unpublished")))
	if err == nil {
		t.Fatal("side update unexpectedly replaced the directory")
	}
	if pd.Proxies()[0] != current || pd.Version() != 0 {
		t.Fatal("failed update changed the published set")
	}
	assertCandidateRoutines(t, before)
	assertCandidateOpen(t, current)
}

func TestProviderRetirementDiscardsParsedRealCandidate(t *testing.T) {
	parser := candidateParser(t)
	parsed, release := make(chan struct{}), make(chan struct{})
	wrapped := func(data []byte) ([]C.Proxy, error) {
		proxies, err := parser(data)
		if err == nil && proxies[0].Name() == "unpublished" {
			close(parsed)
			<-release
		}
		return proxies, err
	}
	pd, err := NewProxySetProvider("retired", 0, []map[string]any{anyTLSCandidate("current")}, wrapped, resource.NewFileVehicle(t.TempDir()), NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	current := pd.Proxies()[0]
	defer current.Close()
	defer pd.Close()
	before := anyTLSRoutines()
	done := make(chan error, 1)
	data := candidatePayload(t, anyTLSCandidate("unpublished"))
	go func() { _, _, err := pd.SideUpdate(data); done <- err }()
	awaitRetirement(t, parsed)
	pd.Cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("retired parser published: %v", err)
	}
	if err := pd.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pd.Proxies()[0] != current || pd.Version() != 0 {
		t.Fatal("retired update replaced the previous set")
	}
	assertCandidateRoutines(t, before)
	assertCandidateOpen(t, current)
}

func TestProviderDiscardKeepsReusedCurrentAdapter(t *testing.T) {
	parser := candidateParser(t)
	old, err := parser(candidatePayload(t, anyTLSCandidate("current")))
	if err != nil {
		t.Fatal(err)
	}
	current := old[0]
	defer current.Close()
	// Distinct wrappers may borrow the same published transport. Discard must
	// use adapter identity, not proxy name or the outer wrapper identity.
	reused := adapter.NewProxy(current.Adapter())
	pd, err := NewProxySetProvider("reuse", 0, []map[string]any{{"name": "fallback"}}, func([]byte) ([]C.Proxy, error) { return []C.Proxy{reused}, nil }, resource.NewFileVehicle(t.TempDir()), NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	pd.proxies = []C.Proxy{current}
	if _, _, err := pd.SideUpdate([]byte("new data")); err == nil {
		t.Fatal("side update unexpectedly succeeded")
	}
	assertCandidateOpen(t, current)
	assertCandidateOpen(t, reused)
}
