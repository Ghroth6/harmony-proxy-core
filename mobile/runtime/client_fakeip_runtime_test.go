//go:build with_gvisor

package runtime_test

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

func clientTCP4Packet(target net.IP, targetPort, sourcePort uint16, sequence, ack uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.IPv4(10, 111, 0, 1).To4())
	copy(packet[16:20], target.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], targetPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	pseudo := append([]byte{}, packet[12:20]...)
	pseudo = append(pseudo, 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func incrementClientSSNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}

// This independently authenticates the actual SIP004 TCP salt, length and
// payload records using standard crypto, then sends an independently sealed
// response. It does not use any production adapter/cipher/stream helper.
func clientSSStreamExchange(t *testing.T, conn net.Conn, password, host, request, reply string) error {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return err
	}
	aead := clientSSUDPSeal(t, password, salt)
	nonce := make([]byte, aead.NonceSize())
	expected := append(append([]byte{3, byte(len(host))}, []byte(host)...), 1, 187)
	expected = append(expected, []byte(request)...)
	var plain []byte
	for len(plain) < len(expected) {
		lengthRecord := make([]byte, 2+aead.Overhead())
		if _, err := io.ReadFull(conn, lengthRecord); err != nil {
			return err
		}
		decoded, err := aead.Open(nil, nonce, lengthRecord, nil)
		if err != nil {
			return err
		}
		incrementClientSSNonce(nonce)
		length := binary.BigEndian.Uint16(decoded)
		if length > 0x3fff {
			return errors.New("actual SS TCP peer rejected a record length")
		}
		record := make([]byte, int(length)+aead.Overhead())
		if _, err = io.ReadFull(conn, record); err != nil {
			return err
		}
		decoded, err = aead.Open(nil, nonce, record, nil)
		if err != nil {
			return err
		}
		incrementClientSSNonce(nonce)
		plain = append(plain, decoded...)
	}
	if string(plain) != string(expected) {
		return errors.New("actual encrypted TCP stream did not preserve the original fake-IP domain and payload")
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead = clientSSUDPSeal(t, password, salt)
	nonce = make([]byte, aead.NonceSize())
	length := []byte{byte(len(reply) >> 8), byte(len(reply))}
	sealed := aead.Seal(append([]byte{}, salt...), nonce, length, nil)
	incrementClientSSNonce(nonce)
	sealed = aead.Seal(sealed, nonce, []byte(reply), nil)
	_, err := conn.Write(sealed)
	return err
}

func TestClientTUNFakeIPOriginalDomainRuleUsesActualTCPAndJoinsStop(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp4", "127.0.0.1:0", false, clientDNSUnique)
}

func TestClientTUNFakeIPAmbiguousClientQuestionsStayUnattributed(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp4", "127.0.0.1:0", false, clientDNSAmbiguous)
}

func TestClientTUNFakeIPExpiredBeforeConnectionStaysUnattributed(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp4", "127.0.0.1:0", false, clientDNSExpired)
}

func TestClientTUNDefaultDualStackPolicyUsesIPv4NodeWithOriginalDNSIPv6Disabled(t *testing.T) {
	testClientTUNFakeIPTCP(t, "", true, "tcp4", "127.0.0.1:0", false, clientDNSUnique)
}

func TestClientTUNDualStackPolicyUsesIPv6NodeWithOriginalDNSIPv6Disabled(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: true\n", true, "tcp6", "[::1]:0", false, clientDNSUnique)
}

func TestClientTUNIPv4OnlyPolicyRejectsIPv6PhysicalNode(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp6", "[::1]:0", true, clientDNSUnique)
}

type clientDNSLinkMode uint8

const (
	clientDNSUnique clientDNSLinkMode = iota
	clientDNSAmbiguous
	clientDNSExpired
)

func testClientTUNFakeIPTCP(t *testing.T, general string, ipv6 bool, peerNetwork, peerAddress string, rejectNode bool, dnsLink clientDNSLinkMode) {
	t.Helper()
	peer, err := net.Listen(peerNetwork, peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	dnsPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	var bootstrapQueries atomic.Int32
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		packet := make([]byte, 512)
		for {
			n, address, err := dnsPeer.ReadFrom(packet)
			if err != nil {
				return
			}
			question := new(D.Msg)
			if question.Unpack(packet[:n]) != nil || len(question.Question) != 1 || question.Question[0].Name != "ipv6-node.original-policy.test." || question.Question[0].Qtype != D.TypeA {
				t.Error("physical IPv4-only lookup did not preserve the original DNS A-only policy")
				return
			}
			bootstrapQueries.Add(1)
			answer := new(D.Msg).SetReply(question)
			payload, err := answer.Pack()
			if err == nil {
				_, err = dnsPeer.WriteTo(payload, address)
			}
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	t.Cleanup(func() { dnsPeer.Close(); <-dnsDone })
	const password = "fakeip-tcp-fixture-only"
	const host = "tcp.original-policy.test"
	const request = "tcp-fakeip-request"
	const reply = "tcp-fakeip-response"
	verified, physicalEOF := make(chan error, 1), make(chan error, 1)
	peerDone, peerConn := make(chan struct{}), make(chan net.Conn, 1)
	go func() {
		defer close(peerDone)
		conn, err := peer.Accept()
		if err != nil {
			verified <- err
			return
		}
		peerConn <- conn
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		err = clientSSStreamExchange(t, conn, password, host, request, reply)
		verified <- err
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
			physicalEOF <- err
		}
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
	server := peer.Addr().(*net.TCPAddr).IP.String()
	if peerNetwork == "tcp6" {
		// Domain nodes are supported; IPv6 literals are outside the current node gate.
		server = "ipv6-node.original-policy.test"
		general += "hosts: {ipv6-node.original-policy.test: '::1'}\n"
	}
	input := []byte(fmt.Sprintf("%sdns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: ['%s']\n  fallback-filter: {geoip: false}\nproxies:\n  - {name: fakeip-tcp-node, type: ss, server: '%s', port: %d, cipher: aes-128-gcm, password: %s, udp: true}\nproxy-groups:\n  - {name: original-domain-select, type: select, proxies: [fakeip-tcp-node]}\nrules:\n  - DOMAIN-SUFFIX,original-policy.test,original-domain-select\n  - MATCH,REJECT\n", general, dnsPeer.LocalAddr().String(), server, peer.Addr().(*net.TCPAddr).Port, password))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, ipv6))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("actual original source fake-IP candidate did not activate: %+v", started)
	}
	initial := domainWire(t, started)
	if initial.DNS == nil || initial.DNS.Sequence != 0 || initial.DNS.Dropped != 0 || initial.DNS.Saturated || len(initial.DNS.Queries) != 0 {
		t.Fatal("active captured client DNS must expose an empty current-run observation, not unavailable or inherited history")
	}
	question := new(D.Msg).SetQuestion(host+".", D.TypeAAAA)
	question.Id = 6788
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51235, payload))
	select {
	case packet := <-system.output:
		answer := new(D.Msg)
		if len(packet) < 28 || packet[9] != 17 || answer.Unpack(packet[28:]) != nil || answer.Id != 6788 || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 0 {
			t.Fatal("physical node address-family support changed the original DNS ipv6=false answer policy")
		}
	case <-time.After(time.Second):
		t.Fatal("original AAAA suppression did not return through the real TUN pump")
	}
	question = new(D.Msg).SetQuestion(host+".", D.TypeA)
	question.Id = 6789
	payload, err = question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51236, payload))
	var fakeIP net.IP
	select {
	case packet := <-system.output:
		answer := new(D.Msg)
		if len(packet) < 28 || packet[9] != 17 || answer.Unpack(packet[28:]) != nil || answer.Id != 6789 || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 {
			t.Fatal("actual TUN DNS did not return the original fake-IP response")
		}
		fakeIP = answer.Answer[0].(*D.A).A
		addr, valid := netip.AddrFromSlice(fakeIP)
		if !valid || !netip.MustParsePrefix("198.18.0.0/16").Contains(addr.Unmap()) {
			t.Fatal("real original fake-IP pool returned an unrelated address")
		}
	case <-time.After(time.Second):
		t.Fatal("original fake-IP DNS did not return through the real TUN pump")
	}
	if protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
		t.Fatal("preparing/starting or serving fake-IP silently acquired network data")
	}
	dnsObserved := domainWire(t, manager.Query(generation, 1)).DNS
	if dnsObserved == nil || dnsObserved.Sequence != 2 || dnsObserved.Dropped != 0 || dnsObserved.Saturated || len(dnsObserved.Queries) != 2 {
		t.Fatalf("actual TUN questions did not produce bounded same-run DNS observations: %+v", dnsObserved)
	}
	query := dnsObserved.Queries[1]
	if query.Sequence != 2 || query.Transport != "udp" || query.QuestionDigest != domainHash(host) || query.QueryType != D.TypeA || query.Outcome != "response" || query.Rcode != D.RcodeSuccess || query.FailureCode != "" || !query.FakeIP || query.AnswersTruncated || len(query.AnswerAddresses) != 1 || query.AnswerAddresses[0] != fakeIP.String() {
		t.Fatalf("actual fake-IP service mapping was not tied to its normalized question and delivered address: %+v", query)
	}
	expectedQueries, expectedSequence := uint64(2), query.Sequence
	if dnsLink == clientDNSAmbiguous {
		clientDomainQuestion(t, system, host+".", D.TypeA, 51237)
		expectedQueries++
		expectedSequence = 0
	}
	if dnsLink == clientDNSExpired {
		for index := 0; index < 16; index++ {
			clientDomainQuestion(t, system, fmt.Sprintf("before-connect-%d.original-policy.test.", index), D.TypeA, uint16(52100+index))
			expectedQueries++
		}
		expectedSequence = 0
	}
	system.inject(clientTCP4Packet(fakeIP, 443, 51300, 1, 0, 2, nil))
	var serverSequence uint32
	select {
	case synAck := <-system.output:
		if len(synAck) < 40 || synAck[9] != 6 || synAck[33]&0x12 != 0x12 {
			t.Fatal("real fake-IP TCP SYN-ACK was not produced")
		}
		serverSequence = binary.BigEndian.Uint32(synAck[24:28])
	case <-time.After(time.Second):
		t.Fatal("actual fake-IP TCP handshake did not enter gVisor")
	}
	system.inject(clientTCP4Packet(fakeIP, 443, 51300, 2, serverSequence+1, 16, nil))
	system.inject(clientTCP4Packet(fakeIP, 443, 51300, 2, serverSequence+1, 24, []byte(request)))
	var response []byte
	rejected := false
	deadline := time.After(2 * time.Second)
responseLoop:
	for len(response) < len(reply) {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || net.IP(packet[12:16]).String() != fakeIP.String() || net.IP(packet[16:20]).String() != "10.111.0.1" {
				t.Fatal("actual fake-IP TCP writeback changed the original TUN tuple")
			}
			ipLength := int(packet[0]&15) * 4
			tcpLength := int(packet[ipLength+12]>>4) * 4
			if packet[ipLength+13]&5 != 0 {
				rejected = true
				break responseLoop
			}
			body := packet[ipLength+tcpLength:]
			if len(body) != 0 {
				sequence := binary.BigEndian.Uint32(packet[ipLength+4 : ipLength+8])
				if sequence != serverSequence+1+uint32(len(response)) {
					t.Fatal("actual TCP response arrived outside its sequence")
				}
				response = append(response, body...)
				system.inject(clientTCP4Packet(fakeIP, 443, 51300, 2+uint32(len(request)), sequence+uint32(len(body)), 16, nil))
			}
		case <-deadline:
			t.Fatal("actual encrypted original-domain TCP response did not return through TUN")
		}
	}
	if rejectNode {
		if !rejected || len(response) != 0 || bootstrapQueries.Load() == 0 || len(manager.Query(generation, 1).Connections) != 0 {
			t.Fatal("IPv4-only source policy did not reject the IPv6 physical node after an original A-only lookup")
		}
		select {
		case <-peerConn:
			t.Fatal("IPv4-only source policy reached the IPv6 physical peer")
		default:
		}
	} else {
		if rejected || string(response) != reply || bootstrapQueries.Load() != 0 {
			t.Fatal("real fake-IP TCP response bytes were not preserved")
		}
		if err = <-verified; err != nil {
			t.Fatal(err)
		}
		observed := manager.Query(generation, 1)
		if len(observed.Connections) != 1 {
			t.Fatal("real fake-IP TCP flow did not publish its original rule/node observation")
		}
		connection := observed.Connections[0]
		if connection.TargetAddress != fakeIP.String() || connection.TargetIPv4 != fakeIP.String() || connection.AddressFamily != "ipv4" || connection.Rule != "DomainSuffix" || connection.Node != "fakeip-tcp-node" || connection.Upload < int64(len(request)) || connection.Download < int64(len(reply)) || protects.Load() == 0 {
			t.Fatalf("original domain rule was not tied to the raw fake-IP target and authenticated TCP bytes: %+v", connection)
		}
		attribution := domainWire(t, observed).Connections[0].Attribution
		if attribution == nil || attribution.DomainDigest != domainHash(host) || attribution.DNSSequence != expectedSequence || attribution.RulePayloadDigest != domainHash("original-policy.test") || attribution.NodeDigest != domainHash("fakeip-tcp-node") {
			t.Fatalf("actual restored domain, client DNS address and original rule payload were not correlated: %+v", attribution)
		}
		answer := clientDomainQuestion(t, system, host+".", D.TypeA, 51238)
		if len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != fakeIP.String() {
			t.Fatal("repeated real TUN DNS question did not return the same mapped fake-IP")
		}
		expectedQueries++
		if repeated := domainWire(t, manager.Query(generation, 1)); repeated.Connections[0].Attribution.DNSSequence != expectedSequence {
			t.Fatal("a later same-host query must not replace the connection-time attribution or invent an initially unavailable link")
		}
		for index := 0; index < 16; index++ {
			clientDomainQuestion(t, system, fmt.Sprintf("fresh-%d.original-policy.test.", index), D.TypeA, uint16(52000+index))
			expectedQueries++
		}
		clientDomainQuestion(t, system, host+".", D.TypeA, 52016)
		expectedQueries++
		evicted := domainWire(t, manager.Query(generation, 1))
		if evicted.DNS.Sequence != expectedQueries || evicted.DNS.Dropped != expectedQueries-16 || evicted.DNS.Saturated || len(evicted.DNS.Queries) != 16 || evicted.Connections[0].Attribution.DNSSequence != expectedSequence {
			t.Fatal("ring churn must preserve only the original confirmed link, without inventing or substituting a later equivalent question")
		}
		if expectedSequence != 0 {
			initial, _ := json.Marshal(query)
			retained, _ := json.Marshal(evicted.DNS.Queries[0])
			if string(initial) != string(retained) {
				t.Fatal("retained DNS result changed fields from the real connection-time service result")
			}
		}
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("fake-IP TCP stop did not join the actual client and physical owners: %+v", stopped)
	}
	wantedRetained := int(expectedQueries)
	if wantedRetained > 16 {
		wantedRetained = 16
	}
	if stoppedDNS := domainWire(t, stopped).DNS; stoppedDNS == nil || stoppedDNS.Sequence != expectedQueries || len(stoppedDNS.Queries) != wantedRetained {
		t.Fatal("normal stop lost its own run's bounded diagnostic evidence")
	}
	if !rejectNode {
		select {
		case err = <-physicalEOF:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("normal fake-IP TCP stop did not physically close the real encrypted connection: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("actual encrypted TCP peer remained open after normal stop")
		}
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("fake-IP TCP stop did not close each owned descriptor once")
		}
	}
}
