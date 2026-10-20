//go:build with_gvisor

package runtime_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

// These independent wire views exercise the same public receipt serialization
// as the C ABI, without inspecting the engine or its resolver's private state.
type domainQueryWire struct {
	Sequence         uint64   `json:"sequence"`
	Transport        string   `json:"transport"`
	QuestionDigest   string   `json:"questionDigest"`
	QueryType        uint16   `json:"queryType"`
	Outcome          string   `json:"outcome"`
	Rcode            int      `json:"rcode"`
	FailureCode      string   `json:"failureCode"`
	AnswerAddresses  []string `json:"answerAddresses"`
	FakeIP           bool     `json:"fakeIP"`
	AnswersTruncated bool     `json:"answersTruncated"`
}

type domainDNSWire struct {
	Sequence  uint64            `json:"sequence"`
	Dropped   uint64            `json:"dropped"`
	Saturated bool              `json:"saturated"`
	Queries   []domainQueryWire `json:"queries"`
}

type domainAttributionWire struct {
	DomainDigest      string `json:"domainDigest"`
	DNSSequence       uint64 `json:"dnsSequence"`
	RulePayloadDigest string `json:"rulePayloadDigest"`
	NodeDigest        string `json:"nodeDigest"`
}

type domainReceiptWire struct {
	DNS         *domainDNSWire `json:"dns"`
	Connections []struct {
		Attribution *domainAttributionWire `json:"attribution"`
	} `json:"connections"`
}

func domainWire(t *testing.T, receipt R.Receipt) domainReceiptWire {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var value domainReceiptWire
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func domainHash(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }

func clientDomainQuestion(t *testing.T, system *packetDescriptors, host string, kind, port uint16) *D.Msg {
	t.Helper()
	question := new(D.Msg).SetQuestion(host, kind)
	question.Id = port
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, port, payload))
	deadline := time.After(time.Second)
	for {
		select {
		case packet := <-system.output:
			if len(packet) < 28 || packet[9] != 17 {
				continue // Other active client TCP flows may still acknowledge bytes.
			}
			answer := new(D.Msg)
			if binary.BigEndian.Uint16(packet[20:22]) != 53 || binary.BigEndian.Uint16(packet[22:24]) != port || answer.Unpack(packet[28:]) != nil || answer.Id != port {
				t.Fatal("TUN returned a DNS answer outside the actual client question tuple")
			}
			return answer
		case <-deadline:
			t.Fatal("actual client DNS answer did not return through TUN")
		}
	}
}

func TestClientTUNDNSObservationBoundsAnswersAndClearsNewGenerations(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := make([]byte, 2048)
		for {
			n, address, err := peer.ReadFrom(payload)
			if err != nil {
				return
			}
			question := new(D.Msg)
			if question.Unpack(payload[:n]) != nil || len(question.Question) != 1 {
				return
			}
			answer := new(D.Msg).SetReply(question)
			for index := byte(2); index < 7; index++ {
				answer.Answer = append(answer.Answer, &D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(198, 18, 0, index)})
			}
			encoded, err := answer.Pack()
			if err == nil {
				_, err = peer.WriteTo(encoded, address)
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { peer.Close(); <-done })
	root := t.TempDir()
	for round := 0; round < 3; round++ {
		generation := nextGeneration()
		register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
		owner, err := policyowner.NewEngine(root)
		if err != nil {
			t.Fatal(err)
		}
		system := newPacketDescriptors()
		manager := R.NewManagerWithPolicy(system, &productionGate, owner)
		t.Cleanup(func() { manager.Stop(generation); owner.Close() })
		networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
		enabled := round != 2
		input := []byte(fmt.Sprintf("ipv6: false\ndns:\n enable: %t\n ipv6: false\n enhanced-mode: fake-ip\n fake-ip-range: 198.18.0.1/16\n fake-ip-filter: ['+.private-fixture.test']\n use-hosts: false\n nameserver: ['%s']\n fallback-filter: {geoip: false}\nrules: ['MATCH,REJECT']\n", enabled, peer.LocalAddr().String()))
		started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, enabled, false))
		if started.Outcome != "running" {
			t.Fatalf("actual original DNS candidate failed: %+v", started)
		}
		initial := domainWire(t, started)
		if enabled && (initial.DNS == nil || initial.DNS.Sequence != 0 || len(initial.DNS.Queries) != 0) || !enabled && initial.DNS != nil || len(started.Connections) != 0 {
			t.Fatal("fresh generation inherited a previous DNS/connection history or disguised unavailable DNS as zero")
		}
		if round == 0 {
			answer := clientDomainQuestion(t, system, "MiXeD.Private-Fixture.TEST.", D.TypeA, 53000)
			if len(answer.Answer) != 5 {
				t.Fatal("diagnostic answer cap changed the actual five-address DNS response")
			}
			observed := manager.Query(generation, 1)
			query := domainWire(t, observed).DNS.Queries[0]
			if query.QuestionDigest != domainHash("mixed.private-fixture.test") || query.FakeIP || !query.AnswersTruncated || len(query.AnswerAddresses) != 4 || query.AnswerAddresses[3] != "198.18.0.5" {
				t.Fatalf("normal DNS addresses in the fake-IP range were mislabeled, over-retained or not normalized: %+v", query)
			}
			encoded, _ := json.Marshal(observed)
			if strings.Contains(strings.ToLower(string(encoded)), "private-fixture.test") {
				t.Fatal("runtime diagnostic receipt disclosed the raw client question")
			}
			observed.DNS.Queries[0].AnswerAddresses[0] = "192.0.2.99"
			if manager.Query(generation, 1).DNS.Queries[0].AnswerAddresses[0] != "198.18.0.2" {
				t.Fatal("caller mutation changed the actual bounded runtime observation")
			}
			for index := 1; index < 20; index++ {
				clientDomainQuestion(t, system, fmt.Sprintf("fresh-%d.private-fixture.test.", index), D.TypeA, uint16(53000+index))
			}
			bounded := domainWire(t, manager.Query(generation, 1)).DNS
			if bounded.Sequence != 20 || bounded.Dropped != 4 || bounded.Saturated || len(bounded.Queries) != 16 || bounded.Queries[0].Sequence != 5 || bounded.Queries[15].Sequence != 20 {
				t.Fatalf("DNS history did not truthfully retain the last16 completed results: %+v", bounded)
			}
		}
		stopped := manager.Stop(generation)
		if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) || owner.Close() != nil {
			t.Fatalf("normal stop did not join the actual DNS owners: %+v", stopped)
		}
	}
}
