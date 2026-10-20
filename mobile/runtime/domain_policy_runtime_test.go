//go:build with_gvisor

package runtime_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

func domainTCPExchange(t *testing.T, system *packetDescriptors, target net.IP, port, sourcePort uint16, request, reply string) {
	t.Helper()
	system.inject(clientTCP4Packet(target, port, sourcePort, 1, 0, 2, nil))
	var sequence uint32
	deadline := time.After(2 * time.Second)
	for sequence == 0 {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || binary.BigEndian.Uint16(packet[22:24]) != sourcePort {
				continue
			}
			if packet[33]&0x12 != 0x12 {
				t.Fatal("actual TUN TCP handshake did not return SYN-ACK")
			}
			sequence = binary.BigEndian.Uint32(packet[24:28])
		case <-deadline:
			t.Fatal("actual original-policy TCP handshake did not return")
		}
	}
	system.inject(clientTCP4Packet(target, port, sourcePort, 2, sequence+1, 16, nil))
	system.inject(clientTCP4Packet(target, port, sourcePort, 2, sequence+1, 24, []byte(request)))
	var response []byte
	for len(response) < len(reply) {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || binary.BigEndian.Uint16(packet[22:24]) != sourcePort {
				continue
			}
			if packet[33]&5 != 0 {
				t.Fatal("actual original-rule TCP flow was rejected before its target response")
			}
			ipLength := int(packet[0]&15) * 4
			tcpLength := int(packet[ipLength+12]>>4) * 4
			body := packet[ipLength+tcpLength:]
			if len(body) == 0 {
				continue
			}
			if !net.IP(packet[12:16]).Equal(target) || binary.BigEndian.Uint32(packet[ipLength+4:ipLength+8]) != sequence+1+uint32(len(response)) {
				t.Fatal("actual target reply lost its TUN tuple or TCP sequence")
			}
			response = append(response, body...)
			system.inject(clientTCP4Packet(target, port, sourcePort, 2+uint32(len(request)), sequence+1+uint32(len(response)), 16, nil))
		case <-deadline:
			t.Fatal("fresh target bytes did not return through actual original-policy TUN")
		}
	}
	if string(response) != reply {
		t.Fatal("actual target response bytes changed")
	}
}

func TestClientTUNFullSourceDomainRulesBindProxyDirectResourcesAndSelectedPreference(t *testing.T) {
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		proxy.Close()
		t.Fatal(err)
	}
	const password = "domain-policy-fixture-only"
	const proxyHost = "fresh.proxy-fixture.test"
	const directHost = "fresh.direct-fixture.test"
	const proxyRequest = "fresh-proxy-domain-request"
	const proxyReply = "fresh-authenticated-proxy-response"
	const directRequest = "fresh-direct-domain-request"
	const directReply = "fresh-direct-target-response"
	verified, closed := make(chan error, 2), make(chan error, 2)
	for index, listener := range []net.Listener{proxy, direct} {
		index, listener := index, listener // Package go1.20 retains range variables.
		done := make(chan struct{})
		accepted := make(chan net.Conn, 1)
		go func() {
			defer close(done)
			connection, err := listener.Accept()
			if err != nil {
				verified <- err
				return
			}
			accepted <- connection
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			if index == 0 {
				err = clientSSStreamExchange(t, connection, password, proxyHost, proxyRequest, proxyReply)
			} else {
				body := make([]byte, len(directRequest))
				_, err = io.ReadFull(connection, body)
				if err == nil && string(body) != directRequest {
					err = errors.New("direct target received other bytes")
				}
				if err == nil {
					_, err = connection.Write([]byte(directReply))
				}
			}
			verified <- err
			if err == nil {
				_, err = connection.Read(make([]byte, 1))
				closed <- err
			}
		}()
		t.Cleanup(func() {
			listener.Close()
			select {
			case connection := <-accepted:
				connection.Close()
			default:
			}
			<-done
		})
	}
	dnsPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var physicalQuestions atomic.Int32
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		payload := make([]byte, 2048)
		for {
			n, address, err := dnsPeer.ReadFrom(payload)
			if err != nil {
				return
			}
			question := new(D.Msg)
			if question.Unpack(payload[:n]) != nil || len(question.Question) != 1 || question.Question[0].Name != directHost+"." || question.Question[0].Qtype != D.TypeA {
				t.Error("physical DNS escaped the original direct-target lookup policy")
				return
			}
			physicalQuestions.Add(1)
			answer := new(D.Msg).SetReply(question)
			answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
			encoded, err := answer.Pack()
			if err == nil {
				_, err = dnsPeer.WriteTo(encoded, address)
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { dnsPeer.Close(); <-dnsDone })
	root := t.TempDir()
	owner, err := policyowner.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	input := []byte(fmt.Sprintf(`ipv6: false
profile: {store-selected: true}
dns:
 enable: true
 ipv6: false
 enhanced-mode: fake-ip
 fake-ip-range: 198.18.0.1/16
 use-hosts: false
 nameserver: ['%s']
 fallback-filter: {geoip: false}
proxies:
 - {name: unused-original-node, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: unused-fixture}
 - {name: 节点夹具, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: %s}
proxy-groups:
 - {name: original-domain-select, type: select, proxies: [unused-original-node, 节点夹具]}
 - {name: unused-original-group, type: select, proxies: [DIRECT, REJECT]}
rule-providers:
 D1Routes: {type: file, behavior: classical, format: yaml, path: './original-routes.yaml'}
rules:
 - DOMAIN-SUFFIX,direct-fixture.test,DIRECT
 - RULE-SET,D1Routes,original-domain-select
 - MATCH,REJECT
`, dnsPeer.LocalAddr().String(), proxy.Addr().(*net.TCPAddr).Port, password))
	plan := owner.Plan("full-domain-plan", input, nil)
	if plan.Category != "planned" || plan.ResourcesComplete || len(plan.Requirements) != 1 || len(plan.Groups) != 2 {
		t.Fatalf("complete source policy was not preserved by planning: %+v", plan)
	}
	resource := domainRuleProviderResource(plan.Requirements[0])
	writeDomainRuleProvider(t, root, resource)
	prefs := []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}}
	request, prepared := sealDomainPolicyRequest(t, clientPolicyRequest(t, input, generation, networkGeneration, true, false), plan.InputDigest, resource, prefs)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	started := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
	if started.Outcome != "running" || started.InputDigest != contract.Digest(input) || started.ResourceManifestDigest != prepared.ResourceManifestDigest || started.GroupPreferencesDigest != prepared.GroupPreferencesDigest {
		t.Fatalf("actual full-source context did not activate unchanged: %+v", started)
	}
	proxyAnswer := clientDomainQuestion(t, system, proxyHost+".", D.TypeA, 54001)
	directAnswer := clientDomainQuestion(t, system, directHost+".", D.TypeA, 54002)
	if len(proxyAnswer.Answer) != 1 || len(directAnswer.Answer) != 1 || physicalQuestions.Load() != 0 {
		t.Fatal("client fake-IP questions escaped to physical DNS or did not return")
	}
	proxyIP := proxyAnswer.Answer[0].(*D.A).A
	directIP := directAnswer.Answer[0].(*D.A).A
	domainTCPExchange(t, system, proxyIP, 443, 54101, proxyRequest, proxyReply)
	domainTCPExchange(t, system, directIP, uint16(direct.Addr().(*net.TCPAddr).Port), 54102, directRequest, directReply)
	for index := 0; index < 2; index++ {
		if err = <-verified; err != nil {
			t.Fatal(err)
		}
	}
	observed := manager.Query(generation, 1)
	if len(observed.Connections) != 2 || observed.DNS == nil || observed.DNS.Sequence != 2 || physicalQuestions.Load() != 1 || protects.Load() < 3 || owner.ResourceAcquireCount() != "0" {
		t.Fatalf("full original policy did not preserve both real routes and independent acquisition boundaries: %+v", observed)
	}
	if receipt, err := json.Marshal(observed); err == nil {
		t.Logf("D1_RUNTIME_RECEIPT:%s", receipt)
	} else {
		t.Fatal(err)
	}
	for index, connection := range observed.Connections {
		host, rule, payload, node, leaf, sequence := proxyHost, "RuleSet", "D1Routes", "redacted", "节点夹具", uint64(1)
		if index == 1 {
			host, rule, payload, node, leaf, sequence = directHost, "DomainSuffix", "direct-fixture.test", "DIRECT", "DIRECT", 2
		}
		attribution := connection.Attribution
		if connection.Rule != rule || connection.Node != node || connection.Upload == 0 || connection.Download == 0 || attribution == nil || attribution.DomainDigest != domainHash(host) || attribution.RulePayloadDigest != domainHash(payload) || attribution.NodeDigest != domainHash(leaf) || attribution.DNSSequence != sequence {
			t.Fatalf("actual source resource/rule/leaf did not match its original selected route: %+v", connection)
		}
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("normal full-source stop did not join all real owners: %+v", stopped)
	}
	for index := 0; index < 2; index++ {
		select {
		case err = <-closed:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("normal stop did not physically close target/proxy: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("normal stop left a real target/proxy connection open")
		}
	}
}
