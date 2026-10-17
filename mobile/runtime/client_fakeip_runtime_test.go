//go:build with_gvisor

package runtime_test

import (
	"crypto/rand"
	"encoding/binary"
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
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp4", "127.0.0.1:0", false)
}

func TestClientTUNDefaultDualStackPolicyUsesIPv4NodeWithOriginalDNSIPv6Disabled(t *testing.T) {
	testClientTUNFakeIPTCP(t, "", true, "tcp4", "127.0.0.1:0", false)
}

func TestClientTUNDualStackPolicyUsesIPv6NodeWithOriginalDNSIPv6Disabled(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: true\n", true, "tcp6", "[::1]:0", false)
}

func TestClientTUNIPv4OnlyPolicyRejectsIPv6PhysicalNode(t *testing.T) {
	testClientTUNFakeIPTCP(t, "ipv6: false\n", false, "tcp6", "[::1]:0", true)
}

func testClientTUNFakeIPTCP(t *testing.T, general string, ipv6 bool, peerNetwork, peerAddress string, rejectNode bool) {
	t.Helper()
	peer, err := net.Listen(peerNetwork, peerAddress)
	if err != nil {
		t.Fatal(err)
	}
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
	input := []byte(fmt.Sprintf("%sdns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: [127.0.0.1:9]\n  fallback-filter: {geoip: false}\nproxies:\n  - {name: fakeip-tcp-node, type: ss, server: '%s', port: %d, cipher: aes-128-gcm, password: %s, udp: true}\nproxy-groups:\n  - {name: original-domain-select, type: select, proxies: [fakeip-tcp-node]}\nrules:\n  - DOMAIN-SUFFIX,original-policy.test,original-domain-select\n  - MATCH,REJECT\n", general, peer.Addr().(*net.TCPAddr).IP.String(), peer.Addr().(*net.TCPAddr).Port, password))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, ipv6))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("actual original source fake-IP candidate did not activate: %+v", started)
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
			if packet[ipLength+13]&4 != 0 {
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
		if !rejected || len(response) != 0 || protects.Load() != 0 || len(manager.Query(generation, 1).Connections) != 0 {
			t.Fatal("IPv4-only source policy did not reject the IPv6 physical node before connecting")
		}
		select {
		case <-peerConn:
			t.Fatal("IPv4-only source policy reached the IPv6 physical peer")
		default:
		}
	} else {
		if rejected || string(response) != reply {
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
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("fake-IP TCP stop did not join the actual client and physical owners: %+v", stopped)
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
