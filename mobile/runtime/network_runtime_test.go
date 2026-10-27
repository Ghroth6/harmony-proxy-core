//go:build with_gvisor

package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/protection"
	D "github.com/miekg/dns"
)

func runtimeSnapshot(generation uint64, dns []string) []byte {
	addresses, _ := json.Marshal(dns)
	return []byte(fmt.Sprintf(`{"schemaVersion":1,"generation":%d,"networkId":17,"vpn":false,"online":true,"dns":%s,"interfaces":[{"name":"synthetic0","mtu":1500,"up":true,"addresses":["192.0.2.10/24"],"routes":[{"destination":"0.0.0.0/0","gateway":"192.0.2.1"}]}]}`, generation, addresses))
}

func nodeNetworkRequest(t *testing.T, input []byte, generation, networkGeneration uint64) []byte {
	t.Helper()
	return clientPolicyRequest(t, input, generation, networkGeneration, false, true)
}

func TestRuntimeDomainUsesAcceptedSnapshotProtectedDNSAndRealTLSBeforeJoinedStop(t *testing.T) {
	peer := newTrojanPeer(t, "valid")
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries, protects atomic.Int32
	server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, request *D.Msg) {
		queries.Add(1)
		response := new(D.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			if question.Name != "proxy.example." {
				t.Error("runtime DNS changed the submitted node hostname")
			}
			if question.Qtype == D.TypeA {
				response.Answer = append(response.Answer, &D.A{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			}
		}
		_ = w.WriteMsg(response)
	})}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); _ = packet.Close(); <-serverDone })

	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	manager := newNodePolicyManager(t, system, generation)
	t.Cleanup(func() { assertTrojanStopped(t, manager, generation, system) })
	controller := network.NewController(manager.NetworkBusy)
	previous, _ := platformnetwork.Current()
	networkGeneration := previous.Generation + 1
	published := controller.Submit("runtime-network", runtimeSnapshot(networkGeneration, []string{packet.LocalAddr().String()}))
	if published.Category != "published" || published.Generation != networkGeneration {
		t.Fatal("real snapshot submission failed")
	}
	input := bytes.Replace(trojanBytes(peer), []byte("server: 127.0.0.1"), []byte("server: proxy.example"), 1)
	started := manager.Start(manager.Consume(generation, 1, 9), input, nodeNetworkRequest(t, input, generation, networkGeneration))
	if started.Outcome != "running" || started.NetworkGeneration != networkGeneration || !manager.NetworkBusy() || queries.Load() != 0 || protects.Load() != 0 {
		t.Fatal("runtime must accept the actual epoch without preparation DNS/dials")
	}
	if busy := controller.Submit("runtime-network-busy", runtimeSnapshot(networkGeneration+1, []string{})); busy.Category != "busy" {
		t.Fatal("actual running manager must block network replacement")
	}
	client, done := forwardTrojan(t, generation, context.Background())
	response := make([]byte, len(trojanResponseBytes))
	if _, err := io.ReadFull(client, response); err != nil || string(response) != trojanResponseBytes {
		t.Fatalf("protected DNS and TLS round trip failed: %v", err)
	}
	select {
	case sni := <-peer.verified:
		if sni != "node.example.invalid" {
			t.Fatal("real TLS used a different SNI")
		}
	case <-time.After(time.Second):
		t.Fatal("real peer did not verify authentication and traffic")
	}
	if queries.Load() == 0 || protects.Load() < 2 {
		t.Fatal("actual DNS datagram and TCP socket must both be protected")
	}
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("normal stop returned before forwarding callback joined")
	}
	if manager.NetworkBusy() {
		t.Fatal("joined runtime must release the network transition barrier")
	}
	if next := controller.Submit("runtime-network-clean", runtimeSnapshot(networkGeneration+1, []string{})); next.Category != "published" {
		t.Fatal("clean stop did not permit a new actual snapshot")
	}
}

func TestRuntimeNetworkEpochAndDomainDNSErrorsAreNotReceiptEchoes(t *testing.T) {
	peer := newTrojanPeer(t, "valid")
	input := bytes.Replace(trojanBytes(peer), []byte("server: 127.0.0.1"), []byte("server: proxy.example"), 1)
	previous, _ := platformnetwork.Current()
	networkGeneration := previous.Generation + 1
	if r := network.NewController(nil).Submit("runtime-empty-dns", runtimeSnapshot(networkGeneration, []string{})); r.Category != "published" {
		t.Fatal("valid snapshot with unavailable DNS should publish honestly")
	}
	for _, check := range []struct {
		requested uint64
		code      string
	}{
		{0, "REQUEST_IDENTITY"},
		{networkGeneration + 1, "NETWORK_GENERATION_MISMATCH"},
		{networkGeneration, "NETWORK_DNS_UNAVAILABLE"},
	} {
		generation := nextGeneration()
		register(generation, func(uint64, uint64, uintptr) int32 {
			t.Error("rejected start opened a socket")
			return protection.Success
		})
		system := newPacketDescriptors()
		manager := newNodePolicyManager(t, system, generation)
		started := manager.Start(manager.Consume(generation, 1, 9), input, nodeNetworkRequest(t, input, generation, check.requested))
		outcome := "failed"
		if check.requested == 0 {
			outcome = "rejected"
		}
		if started.Outcome != outcome || started.FailureCode != check.code || started.NetworkGeneration != 0 || peer.accepted.Load() != 0 {
			t.Fatalf("unaccepted epoch cannot be echoed as actual runtime evidence: %+v", started)
		}
		joined := manager.Stop(generation)
		productionGate.Unregister(generation)
		if joined.Cleanup != "complete" || joined.NetworkGeneration != 0 || system.closes[9] != 1 {
			t.Fatal("rejected network epoch did not join descriptor cleanup")
		}
	}
}
