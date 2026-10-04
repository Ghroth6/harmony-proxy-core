package statistic

import (
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type eventConn struct{ C.Conn }

func (*eventConn) Chains() C.Chain           { return C.Chain{"event-node"} }
func (*eventConn) ProviderChains() C.Chain   { return C.Chain{"event-provider"} }
func (*eventConn) RemoteDestination() string { return "example.test:443" }
func (*eventConn) EgressType() C.AdapterType { return C.Direct }
func (*eventConn) Close() error              { return nil }

type eventPacketConn struct{ C.PacketConn }

func (*eventPacketConn) Chains() C.Chain           { return C.Chain{"event-node"} }
func (*eventPacketConn) ProviderChains() C.Chain   { return C.Chain{"event-provider"} }
func (*eventPacketConn) RemoteDestination() string { return "example.test:53" }
func (*eventPacketConn) EgressType() C.AdapterType { return C.Direct }
func (*eventPacketConn) Close() error              { return nil }

func TestConnectionEventsObserveRegisteredShortLivedTrackers(t *testing.T) {
	m := &Manager{}
	var ids []string
	cancel := m.SubscribeConnections(func(c Tracker) {
		if m.Get(c.ID()) != c {
			t.Error("event emitted before tracker was registered")
		}
		if c.Info().Start.IsZero() || c.LastActivity() != c.Info().Start || c.Info().Metadata.RemoteDst == "" {
			t.Error("event emitted before tracker initialization completed")
		}
		ids = append(ids, c.ID())
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	defer cancel()
	NewTCPTracker(&eventConn{}, m, &C.Metadata{}, nil, 5, 6, true)
	NewUDPTracker(&eventPacketConn{}, m, &C.Metadata{}, nil, 7, 8, true)
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("missing unique creation events: %v", ids)
	}
	for _, id := range ids {
		if m.Get(id) != nil {
			t.Fatal("short connection remained active")
		}
	}
	if up, down := m.Total(); up != 12 || down != 14 {
		t.Fatalf("observer changed initial accounting: %d/%d", up, down)
	}
}

func TestConnectionSubscriptionsArePerManagerAndCancellable(t *testing.T) {
	m, other := &Manager{}, &Manager{}
	count := 0
	var cancel func()
	cancel = m.SubscribeConnections(func(c Tracker) { count++; cancel() })
	defer cancel()
	_ = NewTCPTracker(&eventConn{}, other, &C.Metadata{}, nil, 0, 0, false).Close()
	// Internal connections are still observed, but don't become global traffic.
	_ = NewTCPTracker(&eventConn{}, m, &C.Metadata{}, nil, 3, 4, false).Close()
	_ = NewTCPTracker(&eventConn{}, m, &C.Metadata{}, nil, 0, 0, true).Close()
	if count != 1 {
		t.Fatalf("unexpected manager scope/cancellation count: %d", count)
	}
	if up, down := m.Total(); up != 0 || down != 0 {
		t.Fatal("internal traffic leaked into totals")
	}
}

func TestConcurrentConnectionCreationDoesNotLoseEvents(t *testing.T) {
	m := &Manager{}
	var mu sync.Mutex
	seen := map[string]bool{}
	cancel := m.SubscribeConnections(func(c Tracker) {
		if m.Get(c.ID()) != c {
			t.Error("new connection not registered")
		}
		mu.Lock()
		defer mu.Unlock()
		if seen[c.ID()] {
			t.Error("duplicate connection event")
		}
		seen[c.ID()] = true
	})
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = NewTCPTracker(&eventConn{}, m, &C.Metadata{}, nil, 0, 0, false).Close() }()
	}
	wg.Wait()
	if len(seen) != 100 {
		t.Fatalf("received %d creation events", len(seen))
	}
	m.Range(func(Tracker) bool { t.Error("closed tracker remained registered"); return true })
}
