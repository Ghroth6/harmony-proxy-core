//go:build with_gvisor

package runtime_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

func stopClientCapacityRun(manager *R.Manager, generation uint64, system *packetDescriptors) R.Receipt {
	// Keep the syscall substitute consuming stack output just as a platform TUN
	// does. Test storage must not block Write while cleanup closes many endpoints.
	drainDone, drained := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-system.output:
			case <-drainDone:
				return
			}
		}
	}()
	stopped := manager.Stop(generation)
	close(drainDone)
	<-drained
	return stopped
}

func TestClientTUNTCPHandshakeBacklogRecoversWithoutLosingLifetimeOwners(t *testing.T) {
	// This is the pinned sing-tun v0.4.27 gVisor handshake backlog, not a
	// runtime-exported connection capacity used to construct its own expectation.
	const backlog = 1024
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { stopClientCapacityRun(manager, generation, system); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte("ipv6: false\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n")
	if started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false)); started.Outcome != "running" {
		t.Fatalf("actual TCP DNS ingress did not activate: %+v", started)
	}
	target := net.IPv4(10, 111, 0, 2)
	synAck := func(port uint16) uint32 {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case packet := <-system.output:
				if len(packet) >= 40 && packet[9] == 6 && binary.BigEndian.Uint16(packet[22:24]) == port && packet[33]&0x12 == 0x12 {
					return binary.BigEndian.Uint32(packet[24:28])
				}
			case <-deadline:
				t.Fatalf("handshake backlog did not admit source port %d", port)
			}
		}
	}
	// A non-SYN must not consume a scheduled callback reservation.
	system.inject(clientTCP4Packet(target, 53, 53999, 1, 0, 16, nil))
	var firstSequence uint32
	for index := 0; index < backlog; index++ {
		port := uint16(54000 + index)
		system.inject(clientTCP4Packet(target, 53, port, 1, 0, 2, nil))
		sequence := synAck(port)
		if index == 0 {
			firstSequence = sequence
		}
	}
	overflowPort := uint16(54000 + backlog)
	system.inject(clientTCP4Packet(target, 53, overflowPort, 1, 0, 2, nil))
	deadline := time.After(20 * time.Millisecond)
checkBackpressure:
	for {
		select {
		case packet := <-system.output:
			if len(packet) >= 40 && packet[9] == 6 && binary.BigEndian.Uint16(packet[22:24]) == overflowPort && packet[33]&0x12 == 0x12 {
				t.Fatal("full in-flight handshake backlog admitted another constructor")
			}
		case <-deadline:
			break checkBackpressure
		}
	}
	observed := manager.Query(generation, 1)
	if observed.PendingOwners.TCPCallbacks != backlog || observed.PendingOwners.Constructions != backlog {
		t.Fatalf("full handshake backlog lost or fabricated a scheduled callback: %+v", observed.PendingOwners)
	}
	system.inject(clientTCP4Packet(target, 53, 54000, 2, firstSequence+1, 16, nil))
	until := time.Now().Add(time.Second)
	for {
		observed = manager.Query(generation, 1)
		if observed.PendingOwners.DNSWaiters == 1 && observed.PendingOwners.Constructions == backlog-1 {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("completed handshake retained a backlog reservation: %+v", observed.PendingOwners)
		}
		time.Sleep(time.Millisecond)
	}
	// Retrying the ignored SYN now succeeds while the first DNS connection stays
	// alive, so lifetime ownership can exceed the transient handshake backlog.
	system.inject(clientTCP4Packet(target, 53, overflowPort, 1, 0, 2, nil))
	sequence := synAck(overflowPort)
	system.inject(clientTCP4Packet(target, 53, overflowPort, 2, sequence+1, 16, nil))
	until = time.Now().Add(time.Second)
	for {
		observed = manager.Query(generation, 1)
		if observed.PendingOwners.DNSWaiters == 2 && observed.PendingOwners.TCPCallbacks == backlog+1 && observed.PendingOwners.Constructions == backlog-1 {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("backlog recovery rejected a live lifetime owner: %+v", observed.PendingOwners)
		}
		time.Sleep(time.Millisecond)
	}
	stopped := stopClientCapacityRun(manager, generation, system)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("backlog recovery stranded a scheduled or active callback: %+v", stopped)
	}
	t.Logf("pending handshake backlog=%d; retry after completion succeeded with %d lifetime owners; stop joined all callbacks", backlog, backlog+1)
}

func TestClientTUNUDPForwardsBeyondOldFlowCapacityAndJoinsNormalStop(t *testing.T) {
	const flows = R.PacketQueue + 17
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	peerFailures := make(chan error, 1)
	var peerMu sync.Mutex
	physicalPeers := map[string]bool{}
	go func() {
		defer close(peerDone)
		payload := make([]byte, 512)
		for {
			n, source, err := peer.ReadFrom(payload)
			if err != nil {
				return
			}
			peerMu.Lock()
			physicalPeers[source.String()] = true
			peerMu.Unlock()
			if _, err := peer.WriteTo(payload[:n], source); err != nil {
				peerFailures <- err
				return
			}
		}
	}()
	t.Cleanup(func() { peer.Close(); <-peerDone })
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { stopClientCapacityRun(manager, generation, system); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte("ipv6: false\nhosts: {udp-capacity.runtime.test: 127.0.0.1}\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,DIRECT']\n")
	if started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false)); started.Outcome != "running" {
		t.Fatalf("actual TUN UDP candidate did not activate: %+v", started)
	}
	answer := clientDomainQuestion(t, system, "udp-capacity.runtime.test.", D.TypeA, 52999)
	if len(answer.Answer) != 1 {
		t.Fatal("original-policy DNS did not return the UDP target mapping")
	}
	target := &net.UDPAddr{IP: answer.Answer[0].(*D.A).A, Port: peer.LocalAddr().(*net.UDPAddr).Port}
	for index := 0; index < flows; index++ {
		payload := fmt.Sprintf("independent-tun-udp-payload-%d", index)
		sourcePort := uint16(53000 + index)
		system.inject(clientUDP4Packet(target, sourcePort, []byte(payload)))
		select {
		case response := <-system.output:
			if len(response) < 28 || response[9] != 17 || !net.IP(response[12:16]).Equal(target.IP) || binary.BigEndian.Uint16(response[22:24]) != sourcePort || string(response[28:]) != payload {
				t.Fatalf("real TUN UDP flow %d changed its tuple or response", index)
			}
		case err = <-peerFailures:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatalf("real TUN UDP flow %d did not return", index)
		}
	}
	observed := manager.Query(generation, 1)
	peerMu.Lock()
	peerCount := len(physicalPeers)
	peerMu.Unlock()
	if observed.PendingOwners.UDPFlows != flows || observed.ConnectionSnapshot.Active != flows || peerCount != flows || protects.Load() < flows {
		t.Fatalf("actual NAT flows lost lifetime ownership: physical=%d protected=%d active=%d owners=%+v", peerCount, protects.Load(), observed.ConnectionSnapshot.Active, observed.PendingOwners)
	}
	stopped := manager.Stop(generation)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("normal stop did not join all real NAT senders/readers/writebacks: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("runtime descriptor %d was not closed exactly once", fd)
		}
	}
	t.Logf("real TUN UDP round trips=%d; distinct protected physical peers=%d; normal stop reclaimed every NAT owner", flows, peerCount)
}

func TestClientTUNTCPKeepsForwardingBeyondOldTupleCapacityAndJoinsEveryPeer(t *testing.T) {
	// More established connections than the packet queue also distinguishes
	// connection ownership from a transient ingress/backlog budget.
	const connections = R.PacketQueue + 17
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, connections)
	acceptDone := make(chan struct{})
	var workers sync.WaitGroup
	var peerMu sync.Mutex
	var peers []net.Conn
	go func() {
		defer close(acceptDone)
		for {
			conn, err := peer.Accept()
			if err != nil {
				return
			}
			peerMu.Lock()
			peers = append(peers, conn)
			peerMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_, err := io.Copy(conn, conn)
				closed <- err
			}()
		}
	}()
	t.Cleanup(func() {
		peer.Close()
		<-acceptDone
		peerMu.Lock()
		for _, conn := range peers {
			conn.Close()
		}
		peerMu.Unlock()
		workers.Wait()
	})
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { stopClientCapacityRun(manager, generation, system); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte("ipv6: false\nhosts: {capacity.runtime.test: 127.0.0.1}\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,DIRECT']\n")
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" {
		t.Fatalf("actual TUN TCP candidate did not activate: %+v", started)
	}
	answer := clientDomainQuestion(t, system, "capacity.runtime.test.", D.TypeA, 51999)
	if len(answer.Answer) != 1 {
		t.Fatal("local original-policy DNS did not return its fake-IP mapping")
	}
	target := answer.Answer[0].(*D.A).A
	port := uint16(peer.Addr().(*net.TCPAddr).Port)
	for index := 0; index < connections; index++ {
		payload := fmt.Sprintf("independent-tun-tcp-payload-%d", index)
		domainTCPExchange(t, system, target, port, uint16(52000+index), payload, payload)
	}
	observed := manager.Query(generation, 1)
	if observed.ConnectionSnapshot.Active != connections || observed.PendingOwners.TCPCallbacks != connections || observed.PendingOwners.Forwarding != connections || protects.Load() < connections {
		t.Fatalf("established TUN connections lost real peers or lifetime ownership: protected=%d active=%d owners=%+v", protects.Load(), observed.ConnectionSnapshot.Active, observed.PendingOwners)
	}
	stopped := stopClientCapacityRun(manager, generation, system)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("normal stop did not join every actual TCP connection: %+v", stopped)
	}
	for index := 0; index < connections; index++ {
		select {
		case err = <-closed:
			if err != nil {
				t.Fatalf("normal stop did not cleanly close a real TCP peer: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("a physical TCP peer survived normal stop")
		}
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("runtime descriptor %d was not closed exactly once", fd)
		}
	}
	t.Logf("real TUN TCP round trips=%d; active owners=%d; normal stop joined every physical peer", connections, observed.PendingOwners.TCPCallbacks)
}
