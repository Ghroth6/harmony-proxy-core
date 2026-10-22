//go:build with_gvisor

package runtime_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// These are unrelated registry entries at the socket boundary, not mock
// runtime results. The real forwarded TUN flows below remain independent.
type unrelatedQueryConn struct{ C.Conn }

func (*unrelatedQueryConn) Chains() C.Chain           { return C.Chain{"DIRECT"} }
func (*unrelatedQueryConn) ProviderChains() C.Chain   { return nil }
func (*unrelatedQueryConn) RemoteDestination() string { return "127.0.0.1:443" }
func (*unrelatedQueryConn) EgressType() C.AdapterType { return C.Direct }
func (*unrelatedQueryConn) Close() error              { return nil }

func TestRuntimeLongConnectionRemainsObservableAcrossShortConnectionChurnAndClose(t *testing.T) {
	testRuntimeConnectionRetention(t, 0)
}

func TestRuntimeObservationCapacityDoesNotLimitForwardingAndNewGenerationIsEmpty(t *testing.T) {
	testRuntimeConnectionRetention(t, 64)
}

func TestRuntimeQueryByteBudgetReportsOmissionsWithoutLimitingForwarding(t *testing.T) {
	testRuntimeConnectionRetention(t, 2048)
}

func testRuntimeConnectionRetention(t *testing.T, extraCount int) {
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var lock sync.Mutex
	var accepted []net.Conn
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := peer.Accept()
			if err != nil {
				return
			}
			lock.Lock()
			accepted = append(accepted, connection)
			lock.Unlock()
			workers.Add(1)
			go func() { defer workers.Done(); defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	t.Cleanup(func() {
		peer.Close()
		lock.Lock()
		for _, connection := range accepted {
			connection.Close()
		}
		lock.Unlock()
		workers.Wait()
	})
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	network := publishClientNetwork(t, manager)
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	if started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, network, false, false)); started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := uint16(51000)
	connect := func() (net.Conn, <-chan struct{}) {
		sourcePort++
		port := sourcePort
		client, inbound := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			bound.HandleTCPConn(inbound, &C.Metadata{NetWork: C.TCP, Type: C.TUN, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: port,
				DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(peer.Addr().(*net.TCPAddr).Port), RequestContext: context.Background(),
				RawDstAddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.18.0.20:443"))})
		}()
		return client, done
	}
	exchange := func(connection net.Conn, payload string) {
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != payload {
			t.Fatalf("actual DIRECT payload did not return: %v", err)
		}
	}
	long, longDone := connect()
	defer long.Close()
	exchange(long, "initial-long-connection-payload")
	await := func(port uint16, upload int64, state string) R.ConnectionObservation {
		deadline := time.Now().Add(2 * time.Second)
		for {
			receipt := manager.Query(generation, 1)
			seen := map[string]bool{}
			for _, connection := range receipt.Connections {
				if seen[connection.ID] {
					t.Fatal("upstream connection identity repeated")
				}
				seen[connection.ID] = true
				if connection.SourcePort == port && connection.State == state && connection.Upload >= upload && connection.Download >= upload {
					return connection
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("connection source port %d, state %s was lost: %+v", port, state, receipt.Connections)
			}
			time.Sleep(time.Millisecond)
		}
	}
	before := await(51001, int64(len("initial-long-connection-payload")), "active")
	root, err := forwarding.Context(generation)
	if err != nil {
		t.Fatal(err)
	}
	for _, metadata := range []*C.Metadata{
		{Type: C.INNER, NetWork: C.TCP, ForwardingGeneration: generation, RequestContext: root},
		{Type: C.TUN, NetWork: C.TCP, ForwardingGeneration: generation, RequestContext: context.Background()},
		{Type: C.TUN, NetWork: C.TCP, ForwardingGeneration: generation - 1, RequestContext: root},
	} {
		tracker := statistic.NewTCPTracker(&unrelatedQueryConn{}, statistic.DefaultManager, metadata, nil, 77, 88, false)
		t.Cleanup(func() { _ = tracker.Close() })
		if statistic.DefaultManager.Get(tracker.ID()) == nil {
			t.Fatal("unrelated registry fixture was not actually registered")
		}
	}
	if filtered := manager.Query(generation, 1); filtered.ConnectionSnapshot.Active != 1 || len(filtered.Connections) != 1 {
		t.Fatal("internal, unowned or old-run activity was attributed to this TUN run")
	}
	for index := 0; index < 20; index++ {
		short, done := connect()
		exchange(short, "short-background-payload")
		short.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("short forwarded connection did not close")
		}
	}
	baseline := await(before.SourcePort, before.Upload, "active")
	if extraCount > 0 {
		var extra []net.Conn
		var finished []<-chan struct{}
		for index := 0; index < extraCount; index++ {
			connection, done := connect()
			extra = append(extra, connection)
			finished = append(finished, done)
			exchange(connection, "real-payload-beyond-observation-capacity")
		}
		// Every flow has the same destination and a different source port. The
		// authoritative Mihomo registry must remain visible beyond the old
		// 16-result window and 64-observed-active admission limit.
		registered := 0
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			metadata := tracker.Info().Metadata
			if metadata.Type == C.TUN && metadata.ForwardingGeneration == generation && forwarding.Generation(metadata.RequestContext) == generation {
				registered++
			}
			return true
		})
		if registered != extraCount+1 {
			t.Fatalf("real active TUN trackers: want %d got %d", extraCount+1, registered)
		}
		active := func(receipt R.Receipt) []R.ConnectionObservation {
			var values []R.ConnectionObservation
			for _, value := range receipt.Connections {
				if value.State == "active" {
					values = append(values, value)
				}
			}
			return values
		}
		firstReceipt := manager.Query(generation, 1)
		first, second := active(firstReceipt), active(manager.Query(generation, 1))
		if extraCount == 64 && (len(first) != registered || len(first) != len(second)) {
			t.Fatalf("official active connections omitted by runtime query: registry=%d first=%d second=%d", registered, len(first), len(second))
		}
		if firstReceipt.ConnectionSnapshot.Active != uint64(registered) || uint64(len(first))+firstReceipt.ConnectionSnapshot.ActiveOmitted != uint64(registered) || firstReceipt.ConnectionSnapshot.CapturedAt <= 0 {
			t.Fatal("query did not describe the complete current TUN traversal")
		}
		ports := map[uint16]bool{}
		for index, connection := range first {
			if extraCount == 64 && connection.ID != second[index].ID || connection.Protocol != "tcp" || connection.SourceAddress != "10.111.0.1" || ports[connection.SourcePort] ||
				connection.TargetAddress != "198.18.0.20" || connection.TargetPort != 443 || !connection.OriginalDestination || connection.DestinationAddress != "127.0.0.1" || connection.StartedAt <= 0 {
				t.Fatal("upstream identity or same-destination source tuple was lost")
			}
			ports[connection.SourcePort] = true
		}
		encoded, err := json.Marshal(firstReceipt)
		if err != nil || len(encoded) > R.MaxOutputBytes || extraCount == 2048 && firstReceipt.ConnectionSnapshot.ActiveOmitted == 0 {
			t.Fatal("wire budget did not expose actual active omissions")
		}
		if extraCount == 64 {
			t.Logf("D2_QUERY_RECEIPT:%s", encoded)
		}
		// A real active flow still exchanges fresh bytes while query output is
		// incomplete. Truncation cannot cap actual forwarding.
		exchange(long, "fresh-payload-while-query-is-bounded")
		closing := make(chan struct{})
		go func() {
			defer close(closing)
			for index, connection := range extra {
				connection.Close()
				<-finished[index]
			}
		}()
		deadline := time.After(5 * time.Second)
	closingLoop:
		for {
			select {
			case <-closing:
				break closingLoop
			case <-deadline:
				t.Fatal("over-capacity forwarding did not join")
			default:
			}
			query := manager.Query(generation, 1)
			seen := map[string]bool{}
			for _, value := range query.Connections {
				if seen[value.ID] {
					t.Fatal("concurrent close duplicated one UUID as active and history")
				}
				seen[value.ID] = true
			}
		}
		await(before.SourcePort, before.Upload, "active")
		next, done := connect()
		exchange(next, "new-identity-after-actual-owners-close")
		nextValue := await(sourcePort, int64(len("new-identity-after-actual-owners-close")), "active")
		next.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("later forwarding did not join")
		}
		closed := await(sourcePort, nextValue.Upload, "history")
		if closed.ID != nextValue.ID || closed.Download != nextValue.Download {
			t.Fatal("short history lost settled upstream counters")
		}
	}
	exchange(long, "fresh-action-over-the-same-long-connection")
	after := await(before.SourcePort, baseline.Upload+int64(len("fresh-action-over-the-same-long-connection")), "active")
	if after.ID != before.ID || after.StartedAt != before.StartedAt {
		t.Fatal("same active upstream tracker changed identity")
	}
	long.Close()
	select {
	case <-longDone:
	case <-time.After(2 * time.Second):
		t.Fatal("long forwarded connection did not close")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("observation retained actual forwarding owners: %+v", stopped)
	}
	if stopped.ConnectionSnapshot.Active != 0 || stopped.ConnectionSnapshot.HistoryDropped == 0 || len(stopped.Connections) > 16 {
		t.Fatal("finite creation history did not report its gaps after joined stop")
	}
	for _, value := range stopped.Connections {
		if value.State != "history" {
			t.Fatal("stopped history was reported as active")
		}
	}
	nextGeneration := nextGeneration()
	register(nextGeneration, func(uint64, uint64, uintptr) int32 { return protection.Success })
	nextSystem := newPacketDescriptors()
	nextManager := R.NewManagerWithPolicy(nextSystem, &productionGate, owner)
	t.Cleanup(func() { nextManager.Stop(nextGeneration) })
	nextNetwork := publishClientNetwork(t, nextManager)
	started := nextManager.Start(nextManager.Consume(nextGeneration, 1, 9), input, clientPolicyRequest(t, input, nextGeneration, nextNetwork, false, false))
	if started.Outcome != "running" || len(started.Connections) != 0 {
		t.Fatalf("new generation inherited old tracker identity: %+v", started)
	}
	if result := nextManager.Stop(nextGeneration); result.Cleanup != "complete" || result.PendingOwners != (R.PendingOwners{}) {
		t.Fatal("fresh empty generation did not stop")
	}
}
