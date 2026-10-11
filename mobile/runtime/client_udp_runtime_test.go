//go:build with_gvisor

package runtime_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/mobile/network"
	policyowner "github.com/metacubex/mihomo/mobile/policy"
	policy "github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"golang.org/x/crypto/hkdf"
)

// Caller values follow the frozen cross-language canonical JSON contract; the
// product still independently reopens resources and checks all four identities.
func canonicalClientDigest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object any
	if err = json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(object) // map keys sorted at every depth.
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func clientPolicyRequest(t *testing.T, input []byte, generation, networkGeneration uint64, dns, ipv6 bool) []byte {
	t.Helper()
	sum := sha256.Sum256(input)
	inputDigest := "sha256:" + hex.EncodeToString(sum[:])
	platform := policy.Platform{
		RuntimeOptions: policy.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", DNS: dns, IPv6: ipv6, UDP: true},
		PlatformPolicy: policy.PlatformPolicy{Revision: "client-policy-1", AddressFamily: "ipv4", ApplicationIDs: []string{"org.ghroth.clashbox"}},
		TunPolicy:      policy.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500},
	}
	if ipv6 {
		platform.PlatformPolicy.AddressFamily = "dual"
		platform.TunPolicy.IPv6 = &policy.IPv6Policy{Address: "fd00:111::1", PrefixLength: 126, Route: "::"}
	}
	if dns {
		platform.TunPolicy.DNSServers = []string{"10.111.0.2"}
		if ipv6 {
			platform.TunPolicy.DNSServers = append(platform.TunPolicy.DNSServers, "fd00:111::2")
		}
	}
	prepared := &policy.PreparedContext{SchemaVersion: 1, InputDigest: inputDigest, PlannerVersion: "mobile-policy-1", Resources: []policy.Resource{}, Platform: platform, GroupPreferences: []policy.Preference{}}
	prepared.ResourceManifestDigest = canonicalClientDigest(t, map[string]any{"schemaVersion": 1, "plannerVersion": prepared.PlannerVersion, "inputDigest": inputDigest, "resources": prepared.Resources})
	prepared.PlatformPolicyDigest = canonicalClientDigest(t, platform)
	prepared.GroupPreferencesDigest = canonicalClientDigest(t, map[string]any{"inputDigest": inputDigest, "groupPreferences": prepared.GroupPreferences})
	prepared.CandidateDigest = canonicalClientDigest(t, map[string]any{"inputDigest": inputDigest, "resourceManifestDigest": prepared.ResourceManifestDigest, "platformPolicyDigest": prepared.PlatformPolicyDigest, "groupPreferencesDigest": prepared.GroupPreferencesDigest})
	request := R.StartRequest{ContractVersion: 2, OperationID: "client-policy-start", Generation: generation, NetworkGeneration: networkGeneration, TransferID: "1", InputRevision: "source-policy", InputDigest: inputDigest, RuntimeOptions: platform.RuntimeOptions, PlatformPolicy: platform.PlatformPolicy, TunPolicy: platform.TunPolicy, PreparedPolicy: prepared}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func publishClientNetwork(t *testing.T, manager *R.Manager) uint64 {
	t.Helper()
	previous, _ := platformnetwork.Current()
	generation := previous.Generation + 1
	receipt := network.NewController(manager.NetworkBusy).Submit("client-policy-network", runtimeSnapshot(generation, []string{}))
	if receipt.Category != "published" || receipt.Generation != generation {
		t.Fatalf("actual client network epoch not accepted: %+v", receipt)
	}
	return generation
}

func clientUDP4Packet(target net.Addr, sourcePort uint16, payload []byte) []byte {
	peer := target.(*net.UDPAddr)
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.IPv4(10, 111, 0, 1).To4())
	copy(packet[16:20], peer.IP.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], uint16(peer.Port))
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func clientUDP6Packet(target net.Addr, sourcePort uint16, payload []byte) []byte {
	peer := target.(*net.UDPAddr)
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	copy(packet[8:24], net.ParseIP("fd00:111::1").To16())
	copy(packet[24:40], peer.IP.To16())
	binary.BigEndian.PutUint16(packet[40:42], sourcePort)
	binary.BigEndian.PutUint16(packet[42:44], uint16(peer.Port))
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload)))
	copy(packet[48:], payload)
	pseudo := make([]byte, 40)
	copy(pseudo, packet[8:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(8+len(payload)))
	pseudo[39] = 17
	xsum := checksum(append(pseudo, packet[40:]...))
	if xsum == 0 {
		xsum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:48], xsum)
	return packet
}

// An independent SIP004 peer authenticates the actual adapter's UDP datagram.
// It uses standard crypto, not the adapter's packet writer or cipher helper.
func clientSSUDPSeal(t *testing.T, password string, salt []byte) cipher.AEAD {
	t.Helper()
	master := md5.Sum([]byte(password)) // AES-128 EVP_BytesToKey needs one block.
	subkey := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master[:], salt, []byte("ss-subkey")), subkey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestClientTUNUDPUsesOriginalPolicyActualNATAndJoinsNormalStop(t *testing.T) {
	testClientTUNUDPOriginalPolicy(t, false)
}

func TestClientTUNIPv6UDPUsesOriginalIPCIDR6RuleAndActualNAT(t *testing.T) {
	testClientTUNUDPOriginalPolicy(t, true)
}

func testClientTUNUDPOriginalPolicy(t *testing.T, ipv6 bool) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation) })
	networkGeneration := publishClientNetwork(t, manager)
	const password = "client-udp-fixture-only"
	rules := "  - MATCH,original-select\n"
	if ipv6 {
		rules = "  - IP-CIDR6,2001:db8::/32,original-select,no-resolve\n  - MATCH,REJECT\n"
	}
	input := []byte(fmt.Sprintf("ipv6: %t\ndns: {enable: false}\nproxies:\n  - {name: client-udp-node, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: %s, udp: true}\nproxy-groups:\n  - {name: original-select, type: select, proxies: [client-udp-node]}\nrules:\n%s", ipv6, peer.LocalAddr().(*net.UDPAddr).Port, password, rules))
	request := clientPolicyRequest(t, input, generation, networkGeneration, false, ipv6)
	var caller R.StartRequest
	if err = json.Unmarshal(request, &caller); err != nil {
		t.Fatal(err)
	}
	// The document-network destination is never dialled: the only declared rule
	// selects this verified UDP-capable encrypted loopback adapter.
	candidate, err := owner.BuildCandidate(input, *caller.PreparedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ruleCount := 1
	stackName := "gvisor-ipv4-tcp-udp"
	if ipv6 {
		ruleCount, stackName = 2, "gvisor-dual-tcp-udp"
	}
	if candidate.Proxies["client-udp-node"] == nil || !candidate.Proxies["client-udp-node"].SupportUDP() || len(candidate.Rules) != ruleCount || candidate.Rules[0].Adapter() != "original-select" {
		_ = candidate.Discard(context.Background())
		t.Fatal("synthetic source did not construct the sole declared UDP route")
	}
	if err = candidate.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := manager.Start(manager.Consume(generation, 1, 9), input, request)
	if started.Outcome != "running" || !started.ForwardingActive || started.Stack != stackName {
		t.Fatalf("original-policy actual client UDP entry not active: %+v", started)
	}
	target := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 42), Port: 443}
	packetMaker := clientUDP4Packet
	if ipv6 {
		target.IP, packetMaker = net.ParseIP("2001:db8::42"), clientUDP6Packet
	}
	system.inject(packetMaker(target, 51234, []byte("client-udp-through-tun")))
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 256)
	n, client, err := peer.ReadFrom(data)
	if err != nil || n < 39 {
		t.Fatalf("actual policy UDP peer did not receive client data: n=%d err=%v", n, err)
	}
	aead := clientSSUDPSeal(t, password, data[:16])
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), data[16:n], nil)
	addrLength, addrType := 4, byte(1)
	if ipv6 {
		addrLength, addrType = 16, 4
	}
	prefix := 3 + addrLength
	if err != nil || len(plain) < prefix || plain[0] != addrType || net.IP(plain[1:1+addrLength]).String() != target.IP.String() || binary.BigEndian.Uint16(plain[1+addrLength:prefix]) != 443 || string(plain[prefix:]) != "client-udp-through-tun" {
		t.Fatalf("actual encrypted SS datagram did not authenticate the original client destination: %v", err)
	}
	salt := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatal(err)
	}
	aead = clientSSUDPSeal(t, password, salt)
	reply := aead.Seal(salt, make([]byte, aead.NonceSize()), append(append([]byte{}, plain[:prefix]...), []byte("actual-nat-response")...), nil)
	if _, err = peer.WriteTo(reply, client); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-system.output:
		ipHeaderLength, sourceOffset, addressLength := 20, 12, 4
		version, clientIP := byte(4), "10.111.0.1"
		if ipv6 {
			ipHeaderLength, sourceOffset, addressLength = 40, 8, 16
			version, clientIP = 6, "fd00:111::1"
		}
		if len(response) < ipHeaderLength+8 || response[0]>>4 != version || net.IP(response[sourceOffset:sourceOffset+addressLength]).String() != target.IP.String() || net.IP(response[sourceOffset+addressLength:sourceOffset+2*addressLength]).String() != clientIP || binary.BigEndian.Uint16(response[ipHeaderLength:ipHeaderLength+2]) != 443 || binary.BigEndian.Uint16(response[ipHeaderLength+2:ipHeaderLength+4]) != 51234 || string(response[ipHeaderLength+8:]) != "actual-nat-response" {
			t.Fatal("TUN UDP writeback did not preserve the real source and original client tuple")
		}
		if ipv6 {
			pseudo := make([]byte, 40)
			copy(pseudo, response[8:40])
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(response)-40))
			pseudo[39] = 17
			if response[6] != 17 || binary.BigEndian.Uint16(response[46:48]) == 0 || checksum(append(pseudo, response[40:]...)) != 0 {
				t.Fatal("actual IPv6 UDP writeback has an invalid mandatory checksum")
			}
		} else if response[9] != 17 {
			t.Fatal("actual IPv4 writeback is not UDP")
		}
	case <-time.After(time.Second):
		t.Fatal("real UDP NAT response did not return through gVisor and the TUN pump")
	}
	if protects.Load() == 0 {
		t.Fatal("client UDP physical socket bypassed the installed protection generation")
	}
	snapshot, _ := json.Marshal(manager.Query(generation, 1))
	var observed map[string]any
	_ = json.Unmarshal(snapshot, &observed)
	if observed["pendingOwners"].(map[string]any)["udpFlows"] != float64(1) {
		t.Fatal("actual live NAT flow did not retain client writeback ownership")
	}
	connections := observed["connections"].([]any)
	if len(connections) == 0 {
		t.Fatal("actual client UDP flow did not publish original-rule traffic observation")
	}
	connection := connections[len(connections)-1].(map[string]any)
	family, targetIPv4, rule := "ipv4", target.IP.String(), "Match"
	if ipv6 {
		family, targetIPv4, rule = "ipv6", "", "IPCIDR"
	}
	if connection["targetAddress"] != target.IP.String() || connection["addressFamily"] != family || connection["targetIPv4"] != targetIPv4 || connection["rule"] != rule || connection["node"] != "client-udp-node" {
		t.Fatal("source observation did not bind the true TUN destination and original policy match")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("client UDP stop did not join packets, NAT flow and writeback: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal(fmt.Sprintf("client descriptor %d close count %d", fd, system.closes[fd]))
		}
	}
}

func TestClientTUNRejectsUnboundPlatformBeforePublishingAcceptedIdentity(t *testing.T) {
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation) })
	networkGeneration := publishClientNetwork(t, manager)
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: [MATCH,DIRECT]\n")
	var request R.StartRequest
	if err = json.Unmarshal(clientPolicyRequest(t, input, generation, networkGeneration, false, false), &request); err != nil {
		t.Fatal(err)
	}
	// Each platform is valid by itself. The top-level values used by the actual
	// stack must still belong to the independently verified candidate bundle.
	request.PlatformPolicy.Revision = "another-valid-platform"
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	failed := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
	if failed.Outcome != "failed" || failed.FailureCode != "POLICY_IDENTITY_INVALID" || failed.ForwardingActive {
		t.Fatalf("unbound source platform was not rejected before ingress: %+v", failed)
	}
	failed = manager.Stop(generation) // join the normal asynchronous failure cleanup.
	if failed.Cleanup != "complete" || failed.Phase != "stopped" {
		t.Fatalf("rejected source platform did not finish normal retirement: %+v", failed)
	}
	if failed.InputDigest != "" || failed.CandidateDigest != "" || failed.ResourceManifestDigest != "" || failed.PlatformPolicyDigest != "" || failed.GroupPreferencesDigest != "" || failed.NetworkGeneration != 0 {
		t.Fatal("a rejected source request published an accepted bundle or network identity")
	}
	if failed.PendingOwners != (R.PendingOwners{}) || system.closes[9] != 1 || system.closes[40] != 0 || system.closes[41] != 0 || protects.Load() != 0 {
		t.Fatal("platform rejection retained an owner or activated a physical path")
	}
}
