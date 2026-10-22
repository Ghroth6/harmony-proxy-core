//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

func TestClientTUNQueryRetainsCreationDNSBeyondHistoryAndReportsWireLinkOmissions(t *testing.T) {
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
	network := publishClientNetwork(t, manager, "192.0.2.53")
	var source strings.Builder
	source.WriteString("ipv6: false\nhosts:\n")
	for index := 0; index < 17; index++ {
		fmt.Fprintf(&source, "  'dns-%d.query-reuse.test': 127.0.0.1\n", index)
	}
	source.WriteString("dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: false\n  nameserver: ['127.0.0.1:9']\nrules: ['MATCH,DIRECT']\n")
	input := []byte(source.String())
	if started := manager.Start(manager.Consume(generation, 1, 9), input, clientPolicyRequest(t, input, generation, network, true, false)); started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	for index := 0; index < 17; index++ {
		answer := clientDomainQuestion(t, system, fmt.Sprintf("dns-%d.query-reuse.test.", index), D.TypeA, uint16(55100+index))
		if len(answer.Answer) != 1 {
			t.Fatal("actual captured fake-IP service did not answer")
		}
		address, ok := answer.Answer[0].(*D.A)
		if !ok {
			t.Fatal("actual client A result changed type")
		}
		domainTCPExchange(t, system, address.A, uint16(peer.Addr().(*net.TCPAddr).Port), uint16(55200+index), "real-tun-query-payload", "real-tun-query-payload")
	}
	for index := 0; index < 20; index++ {
		clientDomainQuestion(t, system, fmt.Sprintf("churn-%d.query-reuse.test.", index), D.TypeA, uint16(55300+index))
	}
	observed := manager.Query(generation, 1)
	if observed.ConnectionSnapshot.Active != 17 || observed.ConnectionSnapshot.ActiveOmitted != 0 || observed.ConnectionSnapshot.HistoryDropped != 1 || len(observed.Connections) != 17 || observed.DNS == nil || len(observed.DNS.Queries) != 16 {
		t.Fatal("actual TUN activity was limited by history or DNS churn")
	}
	missing := 0
	for _, connection := range observed.Connections {
		index := int(connection.SourcePort) - 55200
		if index < 0 || index >= 17 || connection.Attribution == nil || connection.Attribution.DomainDigest != domainHash(fmt.Sprintf("dns-%d.query-reuse.test", index)) ||
			connection.State != "active" || connection.Protocol != "tcp" || !connection.OriginalDestination || connection.TargetAddress == connection.DestinationAddress || connection.DestinationAddress != "127.0.0.1" || connection.Upload == 0 || connection.Download == 0 {
			t.Fatalf("original TUN and actual resolved facts diverged: %+v", connection)
		}
		if connection.Attribution.DNSSequence == 0 {
			missing++
		} else if connection.Attribution.DNSSequence != uint64(index+1) {
			t.Fatal("a later DNS result replaced the exact creation association")
		}
	}
	encoded, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Snapshot struct {
			LinksOmitted uint64 `json:"dnsLinksOmitted"`
		} `json:"connectionSnapshot"`
	}
	if json.Unmarshal(encoded, &wire) != nil || missing != 1 || wire.Snapshot.LinksOmitted != 1 {
		t.Fatalf("seventeen exact creation links cannot fit sixteen returned DNS records; omission must be explicit: missing=%d summary=%d", missing, wire.Snapshot.LinksOmitted)
	}
	t.Logf("D2_QUERY_RECEIPT:%s", encoded)
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) || stopped.ConnectionSnapshot.Active != 0 || len(stopped.Connections) != 16 {
		t.Fatal("short accounting history prevented real stop or claimed old activity")
	}
}
