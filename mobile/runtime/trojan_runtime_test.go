//go:build with_gvisor

package runtime_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"github.com/metacubex/mihomo/tunnel"
)

const trojanRequestBytes = "request-byte-proof"
const trojanResponseBytes = "response-byte-proof"

// This peer implements the public Trojan TCP wire contract with standard TLS;
// it does not reuse the adapter, its header writer, or its certificate verifier.
// All addresses, credentials and certificate roots are isolated test resources.
type trojanPeer struct {
	listener      net.Listener
	accepted      atomic.Int32
	verified      chan string
	failure       chan error
	closed        chan struct{}
	handshakeSeen chan struct{}
	mode          string
	mu            sync.Mutex
	connections   []net.Conn
	workers       sync.WaitGroup
}

func newTrojanPeer(t *testing.T, mode string) *trojanPeer {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated Trojan test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	oldSystem, oldEmbed := ca.DisableSystemCa, ca.DisableEmbedCa
	ca.DisableSystemCa, ca.DisableEmbedCa = true, true
	ca.ResetCertificate()
	t.Cleanup(func() { ca.DisableSystemCa, ca.DisableEmbedCa = oldSystem, oldEmbed; ca.ResetCertificate() })
	if mode != "untrusted" {
		if err := ca.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))); err != nil {
			t.Fatal(err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"node.example.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mode == "wrong-name" {
		leaf.DNSNames = []string{"other.example.invalid"}
	}
	if mode == "expired" {
		leaf.NotBefore, leaf.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &trojanPeer{listener: listener, verified: make(chan string, 16), failure: make(chan error, 16), closed: make(chan struct{}, 16), handshakeSeen: make(chan struct{}, 16), mode: mode}
	peer.workers.Add(1)
	go func() {
		defer peer.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peer.accepted.Add(1)
			peer.mu.Lock()
			peer.connections = append(peer.connections, conn)
			peer.mu.Unlock()
			peer.workers.Add(1)
			go func() {
				defer peer.workers.Done()
				defer conn.Close()
				defer func() { peer.closed <- struct{}{} }()
				if mode == "eof" {
					// Read the actual ClientHello, then close without a ServerHello.
					// This is an incomplete TLS exchange, never a certificate verdict.
					_, _ = conn.Read(make([]byte, 4096))
					return
				}
				if mode == "record" {
					_, _ = conn.Read(make([]byte, 4096))
					_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
					return
				}
				if mode == "stall" {
					buffer := make([]byte, 4096)
					if n, _ := conn.Read(buffer); n > 0 {
						peer.handshakeSeen <- struct{}{}
					}
					_, _ = io.Copy(io.Discard, conn) // ClientHello enters; server never sends TLS.
					return
				}
				server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
				if err := server.Handshake(); err != nil {
					peer.failure <- err
					return
				}
				header := make([]byte, 68)
				if _, err := io.ReadFull(server, header); err != nil {
					peer.failure <- err
					return
				}
				// SHA224 password authentication; command=TCP, IPv4 1.1.1.1:443.
				hash := sha256.Sum224([]byte("documentation-only"))
				expected := append([]byte(hex.EncodeToString(hash[:])+"\r\n"), 1, 1, 1, 1, 1, 1, 1, 187, '\r', '\n')
				if !bytes.Equal(header, expected) {
					peer.failure <- fmt.Errorf("peer rejected Trojan authentication/header")
					// Reject target service, then let the tested Stop reclaim its
					// live TLS socket. Immediate raw close could reset concurrent
					// request bytes and intentionally manufacture cleanup errors.
					_, _ = io.Copy(io.Discard, server)
					return
				}
				request := make([]byte, len(trojanRequestBytes))
				if _, err := io.ReadFull(server, request); err != nil {
					peer.failure <- err
					return
				}
				if string(request) != trojanRequestBytes {
					peer.failure <- fmt.Errorf("peer received different traffic")
					return
				}
				if _, err := io.WriteString(server, trojanResponseBytes); err != nil {
					peer.failure <- err
					return
				}
				peer.verified <- server.ConnectionState().ServerName
				_, _ = io.Copy(io.Discard, server)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		peer.mu.Lock()
		for _, conn := range peer.connections {
			conn.Close()
		}
		peer.mu.Unlock()
		peer.workers.Wait()
	})
	return peer
}

func trojanBytes(peer *trojanPeer) []byte {
	password := "documentation-only"
	if peer.mode == "wrong-password" {
		password = "incorrect-documentation-only"
	}
	return []byte(fmt.Sprintf("proxies:\n  - {name: sample, type: trojan, server: 127.0.0.1, port: %d, password: %s, sni: node.example.invalid}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n", peer.listener.Addr().(*net.TCPAddr).Port, password))
}

func trojanEnvelope(input []byte, generation uint64) []byte {
	var fields map[string]any
	json.Unmarshal([]byte(envelope()), &fields)
	sum := sha256.Sum256(input)
	fields["inputDigest"], fields["generation"], fields["transferId"] = "sha256:"+hex.EncodeToString(sum[:]), generation, "1"
	encoded, _ := json.Marshal(fields)
	return encoded
}

func startTrojanRun(t *testing.T, peer *trojanPeer, callback protection.Callback) (*R.Manager, uint64, *packetDescriptors) {
	t.Helper()
	generation := nextGeneration()
	register(generation, callback)
	system := newPacketDescriptors()
	manager := R.NewManager(system, &productionGate)
	t.Cleanup(func() { assertTrojanStopped(t, manager, generation, system) })
	input := trojanBytes(peer)
	started := manager.Start(manager.Consume(generation, 1, 9), input, trojanEnvelope(input, generation))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("real Trojan runtime failed to start: %+v", started)
	}
	return manager, generation, system
}

func assertTrojanStopped(t *testing.T, manager *R.Manager, generation uint64, system *packetDescriptors) {
	t.Helper()
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.ForwardingActive || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("Trojan owners not joined: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("descriptor %d not closed exactly once", fd)
		}
	}
}

func forwardTrojan(t *testing.T, generation uint64, ctx context.Context) (net.Conn, <-chan struct{}) {
	t.Helper()
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	client, inbound := net.Pipe()
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		bound.HandleTCPConn(inbound, &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443, RequestContext: ctx})
	}()
	go func() { _, _ = io.WriteString(client, trojanRequestBytes) }()
	return client, done
}

func TestTrojanRuntimeStrictTLSAuthenticationTrafficAndObservation(t *testing.T) {
	peer := newTrojanPeer(t, "valid")
	var protects atomic.Int32
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	client, done := forwardTrojan(t, generation, context.Background())
	response := make([]byte, len(trojanResponseBytes))
	if _, err := io.ReadFull(client, response); err != nil || string(response) != trojanResponseBytes {
		t.Fatalf("actual Trojan round trip failed: %q %v", response, err)
	}
	select {
	case sni := <-peer.verified:
		if sni != "node.example.invalid" {
			t.Fatal("TLS used a different SNI")
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not verify auth/header/traffic")
	}
	query := manager.Query(generation, 1)
	// The client can finish Read before the relay publishes its atomic byte
	// counter. Observe completion through Query rather than racing that Write.
	deadline := time.Now().Add(time.Second)
	for len(query.Connections) == 1 && query.Connections[0].Download < int64(len(trojanResponseBytes)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		query = manager.Query(generation, 1)
	}
	if protects.Load() != 1 || len(query.Connections) != 1 {
		t.Fatalf("protected real forwarding observation absent: %+v", query)
	}
	connection := query.Connections[0]
	if connection.Node != "sample" || connection.Rule != "Match" || connection.TargetIPv4 != "1.1.1.1" || connection.TargetPort != 443 || connection.Upload < int64(len(trojanRequestBytes)) || connection.Download < int64(len(trojanResponseBytes)) {
		t.Fatalf("wrong real route/traffic observation: %+v", connection)
	}
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join forwarding caller")
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("Stop left actual TLS socket open")
	}
}

func TestTrojanRuntimeFailedProtectionNeverConnectsToTLS(t *testing.T) {
	peer := newTrojanPeer(t, "valid")
	protected := make(chan struct{}, 1)
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 {
		select {
		case protected <- struct{}{}:
		default:
		}
		return protection.PlatformFailure
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	select {
	case <-protected:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("Trojan did not enter generation protection")
	}
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed protected dial not joined")
	}
	if peer.accepted.Load() != 0 || len(manager.Query(generation, 1).Connections) != 0 {
		t.Fatal("failed protection connected/published traffic")
	}
}

func TestTrojanRuntimeRejectsInvalidCertificatesAndPasswordWithoutDirectFallback(t *testing.T) {
	for _, mode := range []string{"untrusted", "wrong-name", "expired", "wrong-password"} {
		t.Run(mode, func(t *testing.T) {
			peer := newTrojanPeer(t, mode)
			manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, done := forwardTrojan(t, generation, ctx)
			select {
			case <-peer.failure:
				cancel()
			case <-time.After(time.Second):
				t.Fatal("invalid credential/certificate was not rejected by real TLS peer")
			}
			response := make([]byte, len(trojanResponseBytes))
			if _, err := io.ReadFull(client, response); err == nil {
				t.Fatal("failed authentication/certificate delivered target traffic")
			}
			assertTrojanStopped(t, manager, generation, system)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("failed real TLS forwarding not joined")
			}
			query := manager.Query(generation, 1)
			if mode != "wrong-password" && len(query.Connections) != 0 {
				t.Fatal("failed certificate published successful dial")
			}
			for _, connection := range query.Connections {
				if connection.Node != "sample" || connection.Rule != "Match" || connection.Download != 0 {
					t.Fatalf("failed auth silently fell back or received traffic: %+v", connection)
				}
			}
			select {
			case <-peer.verified:
				t.Fatal("invalid TLS/authentication was accepted")
			default:
			}
		})
	}
}

func TestTrojanTLSHandshakeTimeoutAndStopClosePhysicalSocketAndJoinOwners(t *testing.T) {
	for _, mode := range []string{"timeout", "stop"} {
		t.Run(mode, func(t *testing.T) {
			peer := newTrojanPeer(t, "stall")
			manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
			ctx := context.Background()
			if mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			client, done := forwardTrojan(t, generation, ctx)
			select {
			case <-peer.handshakeSeen:
			case <-time.After(time.Second):
				t.Fatal("TLS ClientHello was not sent through protected socket")
			}
			if mode == "timeout" {
				if _, err := client.Read(make([]byte, 1)); err == nil {
					t.Fatal("stalled TLS handshake returned target bytes")
				}
			}
			assertTrojanStopped(t, manager, generation, system)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("TLS cancellation did not join entry")
			}
			select {
			case <-peer.closed:
			case <-time.After(time.Second):
				t.Fatal("TLS cancellation leaked actual physical socket")
			}
			if len(manager.Query(generation, 1).Connections) != 0 {
				t.Fatal("unfinished TLS handshake published successful connection")
			}
		})
	}
}

func TestTrojanRuntimeRechecksExactBytesAndScopeBeforeAcquiringIngress(t *testing.T) {
	input := []byte("proxies:\n  - {name: sample, type: trojan, server: 192.0.2.1, port: 443, password: documentation-only, sni: node.example.invalid}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n")
	for _, mutation := range []struct {
		name, from, to string
		staleDigest    bool
	}{
		{"different bytes", "documentation-only", "other-documentation-only", true},
		{"strict TLS bypass", "sni: node.example.invalid", "sni: node.example.invalid, skip-cert-verify: true", false},
		{"direct fallback", "proxies: [sample]", "proxies: [sample, DIRECT]", false},
		{"uncovered field", "sni: node.example.invalid", "sni: node.example.invalid, dialer-proxy: DIRECT", false},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			generation := nextGeneration()
			var protected atomic.Int32
			register(generation, func(uint64, uint64, uintptr) int32 { protected.Add(1); return protection.Success })
			system := newPacketDescriptors()
			manager := R.NewManager(system, &productionGate)
			t.Cleanup(func() { manager.Stop(generation); productionGate.Unregister(generation) })
			actual := bytes.Replace(input, []byte(mutation.from), []byte(mutation.to), 1)
			request := trojanEnvelope(actual, generation)
			if mutation.staleDigest {
				request = trojanEnvelope(input, generation)
			}
			manager.Start(manager.Consume(generation, 1, 9), actual, request)
			stopped := manager.Stop(generation)
			code, outcome := "CANDIDATE_RECHECK", "failed"
			if mutation.staleDigest {
				code, outcome = "INPUT_DIGEST", "rejected"
			}
			if stopped.FailureCode != code || stopped.Outcome != outcome || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) || stopped.ForwardingActive {
				t.Fatalf("runtime accepted stale or uncovered Trojan input: %+v", stopped)
			}
			if protected.Load() != 0 || system.closes[9] != 1 || system.closes[40] != 0 || system.closes[41] != 0 {
				t.Fatal("failed recheck acquired ingress/network or lost descriptor ownership")
			}
		})
	}
}
