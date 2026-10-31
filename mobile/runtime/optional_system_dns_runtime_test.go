//go:build with_gvisor

package runtime_test

import (
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/mobile/protection"
	D "github.com/miekg/dns"
)

func TestClientExplicitDNSWorksWithoutSystemDNSSnapshot(t *testing.T) {
	peer := newDNSFailurePeer(t, D.RcodeSuccess)
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	manager := newNodePolicyManager(t, system, generation)
	networkGeneration := publishClientNetwork(t, manager)
	input := []byte(fmt.Sprintf(`ipv6: false
dns:
 enable: true
 ipv6: false
 enhanced-mode: redir-host
 use-hosts: false
 default-nameserver: [127.0.0.1:9]
 nameserver: ['tcp://%s']
 fallback-filter: {geoip: false}
rules: ['MATCH,DIRECT']
`, peer.listener.Addr()))
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, true, false))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("explicit DNS was rejected because unrelated system DNS was absent: %+v", started)
	}
	answer := clientDomainQuestion(t, system, "explicit-dns-fixture.test.", D.TypeA, 53800)
	if answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("explicit DNS did not return its real wire answer through TUN: %+v", answer)
	}
	record, ok := answer.Answer[0].(*D.A)
	if !ok || record.A.String() != "203.0.113.17" {
		t.Fatalf("explicit DNS answer changed: %+v", answer.Answer)
	}
	peer.assertQuestions(t, "explicit-dns-fixture.test")
}

func TestClientServerlessDirectNodeNeedsNoSystemDNS(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	manager := newNodePolicyManager(t, system, generation)
	networkGeneration := publishClientNetwork(t, manager)
	input := []byte("ipv6: false\ndns: {enable: false}\nproxies: [{name: direct-node, type: direct}]\nrules: ['MATCH,direct-node']\n")
	started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, networkGeneration, false, false))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("an absent server field was incorrectly treated as an unresolved domain: %+v", started)
	}
}
