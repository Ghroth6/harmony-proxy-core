//go:build with_gvisor

package runtime_test

import (
	"encoding/binary"
	"errors"
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

func TestClientTUNDNSUsesCapturedOriginalNameserverPolicyAndNormalStop(t *testing.T) {
	policyPeer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defaultPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer defaultPeer.Close()
	peerDone := make(chan error, 1)
	peerFinished := make(chan struct{})
	defer func() { policyPeer.Close(); <-peerFinished }()
	go func() {
		defer close(peerFinished)
		conn, err := policyPeer.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		payload := make([]byte, int(length))
		if err == nil {
			_, err = io.ReadFull(conn, payload)
		}
		question := new(D.Msg)
		if err == nil {
			err = question.Unpack(payload)
		}
		if err == nil && (len(question.Question) != 1 || question.Question[0].Name != "lookup.original-policy.test.") {
			err = fmt.Errorf("actual original nameserver-policy received another question")
		}
		if err == nil {
			answer := new(D.Msg).SetReply(question)
			answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 15)}}
			payload, err = answer.Pack()
			if err == nil {
				err = binary.Write(conn, binary.BigEndian, uint16(len(payload)))
			}
			if err == nil {
				_, err = conn.Write(payload)
			}
		}
		peerDone <- err
	}()
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	// The external platform snapshot is synthetic fixture metadata; every real
	// DNS socket goes only to the declared loopback peer below.
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte(fmt.Sprintf("ipv6: false\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: normal\n  use-hosts: false\n  default-nameserver: [%s]\n  nameserver: [udp://%s]\n  nameserver-policy:\n    '+.original-policy.test': [tcp://%s]\nrules:\n  - MATCH,REJECT\n", defaultPeer.LocalAddr().String(), defaultPeer.LocalAddr().String(), policyPeer.Addr().String()))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("actual original source DNS candidate did not activate: %+v", started)
	}
	if protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
		t.Fatal("source start performed an implicit DNS dial or resource acquisition")
	}
	question := new(D.Msg).SetQuestion("lookup.original-policy.test.", D.TypeA)
	question.Id = 5678
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51235, payload))
	select {
	case response := <-system.output:
		answer := new(D.Msg)
		if len(response) < 28 || net.IP(response[12:16]).String() != "10.111.0.2" || binary.BigEndian.Uint16(response[20:22]) != 53 || binary.BigEndian.Uint16(response[22:24]) != 51235 || answer.Unpack(response[28:]) != nil || answer.Id != 5678 || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "203.0.113.15" {
			t.Fatal("TUN DNS did not return the actual original nameserver-policy answer")
		}
	case <-time.After(time.Second):
		t.Fatal("actual original DNS service response did not return through TUN")
	}
	if err = <-peerDone; err != nil {
		t.Fatal(err)
	}
	_ = defaultPeer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err = defaultPeer.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatal("source nameserver-policy escaped to the default DNS provider")
	}
	if protects.Load() == 0 {
		t.Fatal("source DNS physical TCP socket bypassed actual protection")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("source TUN DNS did not join real waiters and physical reads: %+v", stopped)
	}
	if owner.ResourceAcquireCount() != "0" {
		t.Fatal("querying or stopping DNS acquired a policy resource")
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("DNS runtime did not close each transferred descriptor once")
		}
	}
}

func TestClientTUNTCPDNSKeepsIdleReadOwnedUntilNormalStop(t *testing.T) {
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte("ipv6: false\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nrules:\n  - MATCH,REJECT\n")
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("actual captured TCP DNS candidate did not activate: %+v", started)
	}
	target := net.IPv4(10, 111, 0, 2)
	system.inject(clientTCP4Packet(target, 53, 51301, 1, 0, 2, nil))
	var serverSequence uint32
	select {
	case synAck := <-system.output:
		if len(synAck) < 40 || synAck[9] != 6 || synAck[33]&0x12 != 0x12 {
			t.Fatal("real client TCP DNS SYN-ACK was not produced")
		}
		serverSequence = binary.BigEndian.Uint32(synAck[24:28])
	case <-time.After(time.Second):
		t.Fatal("real client TCP DNS did not enter gVisor")
	}
	system.inject(clientTCP4Packet(target, 53, 51301, 2, serverSequence+1, 16, nil))
	question := new(D.Msg).SetQuestion("idle-tcp.original-policy.test.", D.TypeA)
	question.Id = 7890
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed, uint16(len(payload)))
	copy(framed[2:], payload)
	system.inject(clientTCP4Packet(target, 53, 51301, 2, serverSequence+1, 24, framed))
	var response []byte
	deadline := time.After(time.Second)
	for len(response) < 2 || len(response) < 2+int(binary.BigEndian.Uint16(response)) {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || net.IP(packet[12:16]).String() != target.String() {
				t.Fatal("actual TCP DNS reply changed its virtual DNS tuple")
			}
			ipLength := int(packet[0]&15) * 4
			tcpLength := int(packet[ipLength+12]>>4) * 4
			body := packet[ipLength+tcpLength:]
			if len(body) != 0 {
				sequence := binary.BigEndian.Uint32(packet[ipLength+4 : ipLength+8])
				if sequence != serverSequence+1+uint32(len(response)) {
					t.Fatal("actual TCP DNS reply arrived outside its sequence")
				}
				response = append(response, body...)
				system.inject(clientTCP4Packet(target, 53, 51301, 2+uint32(len(framed)), sequence+uint32(len(body)), 16, nil))
			}
		case <-deadline:
			t.Fatal("actual captured TCP DNS response did not return through TUN")
		}
	}
	answer := new(D.Msg)
	if answer.Unpack(response[2:]) != nil || answer.Id != 7890 || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatal("real captured TCP DNS did not preserve its frame and answer")
	}
	observed := manager.Query(generation, 1)
	if observed.PendingOwners.DNSWaiters != 1 || observed.PendingOwners.TCPCallbacks != 1 || observed.PendingOwners.Forwarding != 0 || len(observed.Connections) != 0 {
		t.Fatalf("idle DNS client read lost its real waiter/callback owner: %+v", observed)
	}
	stopStarted := time.Now()
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("normal stop did not join the actual idle client DNS read: %+v", stopped)
	}
	if time.Since(stopStarted) > time.Second {
		t.Fatal("normal stop waited for the client DNS read timeout instead of closing the real endpoint")
	}
	if protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
		t.Fatal("real fake-IP TCP DNS used an implicit physical network or resource fetch")
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("client TCP DNS normal stop did not close each owned descriptor once")
		}
	}
}

func TestClientTUNDNSStopJoinsActualPhysicalReadWithoutLateReply(t *testing.T) {
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen, closed := make(chan error, 1), make(chan error, 1)
	peerDone, peerConn := make(chan struct{}), make(chan net.Conn, 1)
	go func() {
		defer close(peerDone)
		conn, err := peer.Accept()
		if err != nil {
			seen <- err
			return
		}
		peerConn <- conn
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		payload := make([]byte, int(length))
		if err == nil {
			_, err = io.ReadFull(conn, payload)
		}
		question := new(D.Msg)
		if err == nil {
			err = question.Unpack(payload)
		}
		if err == nil && (len(question.Question) != 1 || question.Question[0].Name != "cancel.original-policy.test.") {
			err = errors.New("actual physical DNS peer received an unrelated question")
		}
		seen <- err
		if err != nil {
			return
		}
		_, err = conn.Read(make([]byte, 1))
		closed <- err // runtime's actual Close, before the fixture's deferred Close.
	}()
	t.Cleanup(func() {
		peer.Close()
		select {
		case conn := <-peerConn:
			conn.Close()
		default:
		}
		<-peerDone
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
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte(fmt.Sprintf("ipv6: false\ndns:\n  enable: true\n  ipv6: false\n  use-hosts: false\n  default-nameserver: [127.0.0.1:9]\n  nameserver: [tcp://%s]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n", peer.Addr().String()))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("actual in-flight captured DNS candidate did not activate: %+v", started)
	}
	question := new(D.Msg).SetQuestion("cancel.original-policy.test.", D.TypeA)
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51237, payload))
	select {
	case err = <-seen:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual captured DNS query did not enter the physical peer")
	}
	observed := manager.Query(generation, 1)
	if observed.PendingOwners.DNSWaiters != 1 || observed.PendingOwners.UDPPackets != 1 || protects.Load() == 0 {
		t.Fatalf("actual in-flight DNS read lost its client buffer/waiter owner: %+v", observed)
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) || owner.ResourceAcquireCount() != "0" {
		t.Fatalf("normal stop did not join captured DNS client and physical workers: %+v", stopped)
	}
	select {
	case err = <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("claimed normal stop did not actually close the DNS socket: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual DNS physical socket remained open after normal stop")
	}
	select {
	case <-system.output:
		t.Fatal("cancelled captured DNS wrote a late success or synthetic failure packet to TUN")
	case <-time.After(20 * time.Millisecond):
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("in-flight DNS stop did not close each owned descriptor once")
		}
	}
}

func TestClientTUNDualDNSPreservesOriginalAAAASuppression(t *testing.T) {
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte("ipv6: true\ndns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n")
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, true))
	if started.Outcome != "running" || started.Stack != "gvisor-dual-tcp-udp" {
		t.Fatalf("actual dual source DNS candidate did not activate: %+v", started)
	}
	question := new(D.Msg).SetQuestion("ipv6-dns.original-policy.test.", D.TypeAAAA)
	question.Id = 8901
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP6Packet(&net.UDPAddr{IP: net.ParseIP("fd00:111::2"), Port: 53}, 51238, payload))
	select {
	case packet := <-system.output:
		answer := new(D.Msg)
		if len(packet) < 48 || packet[0]>>4 != 6 || packet[6] != 17 || net.IP(packet[8:24]).String() != "fd00:111::2" || net.IP(packet[24:40]).String() != "fd00:111::1" || answer.Unpack(packet[48:]) != nil || answer.Id != 8901 || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 0 {
			t.Fatal("IPv6 client DNS transport changed original DNS ipv6=false answer semantics")
		}
		pseudo := make([]byte, 40)
		copy(pseudo, packet[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)-40))
		pseudo[39] = 17
		if binary.BigEndian.Uint16(packet[46:48]) == 0 || checksum(append(pseudo, packet[40:]...)) != 0 {
			t.Fatal("actual IPv6 client DNS response omitted its required valid UDP checksum")
		}
	case <-time.After(time.Second):
		t.Fatal("actual IPv6 virtual DNS did not return through TUN")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) || protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
		t.Fatalf("dual fake-IP DNS did not retain original policy and join normal stop: %+v", stopped)
	}
}

func TestClientTUNDNSCapacityStillAllowsStopAndJoinsEveryRealPeer(t *testing.T) {
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen, closed := make(chan error, 64), make(chan error, 64)
	acceptDone := make(chan struct{})
	var workers sync.WaitGroup
	var peerMu sync.Mutex
	var conns []net.Conn
	var accepted atomic.Int32
	go func() {
		defer close(acceptDone)
		for {
			conn, err := peer.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			peerMu.Lock()
			conns = append(conns, conn)
			peerMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var length uint16
				err := binary.Read(conn, binary.BigEndian, &length)
				payload := make([]byte, int(length))
				if err == nil {
					_, err = io.ReadFull(conn, payload)
				}
				if err == nil {
					err = new(D.Msg).Unpack(payload)
				}
				seen <- err
				if err == nil {
					_, err = conn.Read(make([]byte, 1))
					closed <- err
				}
			}()
		}
	}()
	t.Cleanup(func() {
		peer.Close()
		<-acceptDone
		peerMu.Lock()
		for _, conn := range conns {
			conn.Close()
		}
		peerMu.Unlock()
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
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte(fmt.Sprintf("ipv6: false\ndns:\n  enable: true\n  ipv6: false\n  use-hosts: false\n  default-nameserver: [127.0.0.1:9]\n  nameserver: [tcp://%s]\n  fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n", peer.Addr().String()))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" {
		t.Fatalf("actual DNS capacity candidate did not activate: %+v", started)
	}
	for index := 0; index < R.MaxDNSWaiters; index++ {
		question := new(D.Msg).SetQuestion(fmt.Sprintf("capacity-%d.original-policy.test.", index), D.TypeA)
		payload, err := question.Pack()
		if err != nil {
			t.Fatal(err)
		}
		system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, uint16(51500+index), payload))
	}
	deadline := time.After(2 * time.Second)
	for index := 0; index < R.MaxDNSWaiters; index++ {
		select {
		case err = <-seen:
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("actual physical DNS peers did not reach the bounded waiter capacity")
		}
	}
	question := new(D.Msg).SetQuestion("over-capacity.original-policy.test.", D.TypeA)
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51600, payload))
	time.Sleep(20 * time.Millisecond)
	observed := manager.Query(generation, 1)
	if observed.PendingOwners.DNSWaiters != R.MaxDNSWaiters || observed.PendingOwners.UDPPackets != R.MaxDNSWaiters || accepted.Load() != R.MaxDNSWaiters {
		t.Fatalf("DNS capacity admitted another real socket or lost a live worker: accepted=%d owners=%+v", accepted.Load(), observed.PendingOwners)
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) || owner.ResourceAcquireCount() != "0" {
		t.Fatalf("full DNS capacity prevented actual normal stop: %+v", stopped)
	}
	for index := 0; index < R.MaxDNSWaiters; index++ {
		select {
		case err = <-closed:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("normal stop did not physically close every actual DNS socket: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("an actual DNS socket survived capacity stop")
		}
	}
}
