//go:build with_gvisor

package runtime_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"github.com/metacubex/mihomo/tunnel"
)

func TestRuntimeLongConnectionRemainsObservableAcrossShortConnectionChurnAndClose(t *testing.T) {
	testRuntimeConnectionRetention(t, false)
}

func TestRuntimeObservationCapacityDoesNotLimitForwardingAndNewGenerationIsEmpty(t *testing.T) {
	testRuntimeConnectionRetention(t, true)
}

func testRuntimeConnectionRetention(t *testing.T, overload bool) {
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
	connect := func() (net.Conn, <-chan struct{}) {
		client, inbound := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			bound.HandleTCPConn(inbound, &C.Metadata{NetWork: C.TCP, Type: C.TUN, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: 51001,
				DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(peer.Addr().(*net.TCPAddr).Port), RequestContext: context.Background()})
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
	await := func(sequence uint64, upload int64) R.ConnectionObservation {
		deadline := time.Now().Add(2 * time.Second)
		for {
			receipt := manager.Query(generation, 1)
			if len(receipt.Connections) > 16 {
				t.Fatal("connection receipt exceeded its existing bound")
			}
			seen := map[uint64]bool{}
			for _, connection := range receipt.Connections {
				if seen[connection.Sequence] {
					t.Fatal("connection sequence repeated")
				}
				seen[connection.Sequence] = true
				if connection.Sequence == sequence && connection.Upload >= upload && connection.Download >= upload {
					return connection
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("active or recently ended long connection %d was lost after churn: %+v", sequence, receipt.Connections)
			}
			time.Sleep(time.Millisecond)
		}
	}
	before := await(1, int64(len("initial-long-connection-payload")))
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
	baseline := await(before.Sequence, before.Upload)
	if overload {
		var extra []net.Conn
		var finished []<-chan struct{}
		for index := 0; index < 64; index++ {
			connection, done := connect()
			extra = append(extra, connection)
			finished = append(finished, done)
			exchange(connection, "real-payload-beyond-observation-capacity")
		}
		// 1 long + 20 ended + 63 other active identities reach sequence 84.
		// The 65th active connection still forwarded real bytes above, without
		// enlarging the observer's existing TCP+UDP capacity of 64 identities.
		first := manager.Query(generation, 1).Connections
		second := manager.Query(generation, 1).Connections
		if len(first) > 16 || len(first) != len(second) {
			t.Fatal("bounded selection changed without connection activity")
		}
		for index, connection := range first {
			if connection.Sequence > 84 || connection.Sequence != second[index].Sequence {
				t.Fatal("over-capacity observer grew or stable sequence changed")
			}
		}
		for index, connection := range extra {
			connection.Close()
			select {
			case <-finished[index]:
			case <-time.After(2 * time.Second):
				t.Fatal("over-capacity forwarding did not join")
			}
		}
		await(before.Sequence, before.Upload)
		next, done := connect()
		exchange(next, "new-identity-after-actual-owners-close")
		await(85, int64(len("new-identity-after-actual-owners-close")))
		next.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("later forwarding did not join")
		}
	}
	exchange(long, "fresh-action-over-the-same-long-connection")
	after := await(before.Sequence, baseline.Upload+int64(len("fresh-action-over-the-same-long-connection")))
	long.Close()
	select {
	case <-longDone:
	case <-time.After(2 * time.Second):
		t.Fatal("long forwarded connection did not close")
	}
	closed := await(before.Sequence, after.Upload)
	if closed.Upload != after.Upload || closed.Download != after.Download {
		t.Fatal("ended observation lost the same connection's settled totals")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("observation retained actual forwarding owners: %+v", stopped)
	}
	retained := false
	for _, connection := range stopped.Connections {
		if connection.Sequence == before.Sequence {
			retained = connection.Upload == closed.Upload && connection.Download == closed.Download
		}
	}
	if !retained {
		t.Fatal("joined stop lost the same long connection's final sequence or counters")
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
