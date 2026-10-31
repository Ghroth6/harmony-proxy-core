//go:build with_gvisor

package runtime_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	L "github.com/metacubex/mihomo/log"
	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

const sourceTLSName = "node.example.invalid"
const sourceTLSPassword = "source-policy-fixture-only"
const sourceTLSRequest = "fresh-domain-request-through-node-tls"
const sourceTLSResponse = "authenticated-node-tls-domain-response"

type sourceTLSHandshake struct {
	sni             string
	certificateSent bool
	err             error
}

// TLS 1.2 keeps the Certificate handshake observable at this independent peer.
// Recording a successful socket write containing the exact leaf DER, together
// with the client's real typed x509 error, excludes a pre-certificate EOF peer.
// This fixture intentionally does not claim coverage of all TLS variants.
type sourceTLSWire struct {
	net.Conn
	leafDER []byte
	sent    bool
}

func (c *sourceTLSWire) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if bytes.Contains(data[:n], c.leafDER) {
		c.sent = true
	}
	return n, err
}

type sourceTLSPeer struct {
	listener      net.Listener
	handshakes    chan sourceTLSHandshake
	closed        chan error
	authenticated atomic.Int32
	targetBytes   atomic.Int32
}

func sourceTLSCertificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{encoded, parent.Raw}, PrivateKey: key}, encoded
}

func sourceTLSRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated full-source TLS root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	encoded, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return root, key
}

func newSourceTLSPeer(t *testing.T, certificate tls.Certificate, leafDER []byte) *sourceTLSPeer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The original tunnel may retry a failed node dial. Keep enough bounded peer
	// records for those real attempts without blocking its certificate exchange.
	peer := &sourceTLSPeer{listener: listener, handshakes: make(chan sourceTLSHandshake, 32), closed: make(chan error, 32)}
	var workers sync.WaitGroup
	var lock sync.Mutex
	var connections []net.Conn
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			lock.Lock()
			connections = append(connections, connection)
			lock.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				wire := &sourceTLSWire{Conn: connection, leafDER: leafDER}
				var sni string
				server := tls.Server(wire, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
					GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni = hello.ServerName; return nil, nil }})
				err := server.Handshake()
				peer.handshakes <- sourceTLSHandshake{sni: sni, certificateSent: wire.sent, err: err}
				if err != nil {
					peer.closed <- err
					return
				}
				// Independently decode the public Trojan TCP/domain wire format.
				header := make([]byte, 61)
				if _, err = io.ReadFull(server, header); err == nil {
					hash := sha256.Sum224([]byte(sourceTLSPassword))
					if string(header[:58]) != hex.EncodeToString(hash[:])+"\r\n" || header[58] != 1 || header[59] != 3 {
						err = errors.New("peer rejected Trojan authentication or domain command")
					}
				}
				if err == nil {
					target := make([]byte, int(header[60])+4)
					_, err = io.ReadFull(server, target)
					if err == nil && (!bytes.HasSuffix(target[:len(target)-4], []byte(".proxy-fixture.test")) || binary.BigEndian.Uint16(target[len(target)-4:]) != 443 || string(target[len(target)-2:]) != "\r\n") {
						err = errors.New("peer received a different domain target")
					}
				}
				if err == nil {
					peer.authenticated.Add(1)
					request := make([]byte, len(sourceTLSRequest))
					_, err = io.ReadFull(server, request)
					if err == nil && string(request) != sourceTLSRequest {
						err = errors.New("peer received different fresh target bytes")
					}
				}
				if err == nil {
					var n int
					n, err = io.WriteString(server, sourceTLSResponse)
					peer.targetBytes.Add(int32(n))
				}
				if err == nil {
					_, err = server.Read(make([]byte, 1)) // Normal Stop must close this real socket.
				}
				peer.closed <- err
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		lock.Lock()
		for _, connection := range connections {
			connection.Close()
		}
		lock.Unlock()
		workers.Wait()
	})
	return peer
}

func sourceTLSInput(peer *sourceTLSPeer, nameserver string) []byte {
	return []byte(fmt.Sprintf(`ipv6: false
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
 - {name: source-tls-node, type: trojan, server: 127.0.0.1, port: %d, password: %s, sni: node.example.invalid, skip-cert-verify: false}
proxy-groups:
 - {name: original-domain-select, type: select, proxies: [unused-original-node, source-tls-node]}
 - {name: unused-original-group, type: select, proxies: [DIRECT, REJECT]}
rule-providers:
 D1Routes: {type: file, behavior: classical, format: yaml, path: './original-routes.yaml'}
rules:
 - DOMAIN-SUFFIX,direct-fixture.test,DIRECT
 - RULE-SET,D1Routes,original-domain-select
 - MATCH,REJECT
`, nameserver, peer.listener.Addr().(*net.TCPAddr).Port, sourceTLSPassword))
}

func startSourceTLS(t *testing.T, owner *policyowner.Engine, root string, input []byte, protects *atomic.Int32) (*R.Manager, uint64, *packetDescriptors, R.Receipt) {
	t.Helper()
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { assertTrojanStopped(t, manager, generation, system) })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	plan := owner.Plan("source-tls-plan", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 || len(plan.Groups) != 2 || len(plan.Groups[0].Members) != 2 {
		t.Fatalf("full source structure was not retained: %+v", plan)
	}
	resource := domainRuleProviderResource(plan.Requirements[0])
	writeDomainRuleProvider(t, root, resource)
	preferences := []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}}
	request, prepared := sealDomainPolicyRequest(t, clientPolicyRequest(t, input, generation, networkGeneration, true, false), plan.InputDigest, resource, preferences)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	started := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
	if started.Outcome != "running" || !started.ForwardingActive || started.InputDigest != contract.Digest(input) || started.CandidateDigest != prepared.CandidateDigest || started.ResourceManifestDigest != prepared.ResourceManifestDigest || started.GroupPreferencesDigest != prepared.GroupPreferencesDigest {
		t.Fatalf("original source identities did not activate: %+v", started)
	}
	return manager, generation, system, started
}

func rejectedSourceTLSRequest(t *testing.T, system *packetDescriptors, target net.IP, sourcePort uint16) {
	t.Helper()
	system.inject(clientTCP4Packet(target, 443, sourcePort, 1, 0, 2, nil))
	deadline := time.After(15 * time.Second)
	for {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || binary.BigEndian.Uint16(packet[22:24]) != sourcePort {
				continue
			}
			if packet[33]&0x12 != 0x12 {
				t.Fatal("actual rejected TLS flow did not enter TUN TCP")
			}
			sequence := binary.BigEndian.Uint32(packet[24:28])
			system.inject(clientTCP4Packet(target, 443, sourcePort, 2, sequence+1, 16, nil))
			system.inject(clientTCP4Packet(target, 443, sourcePort, 2, sequence+1, 24, []byte(sourceTLSRequest)))
			goto entered
		case <-deadline:
			t.Fatal("actual rejected TLS flow did not acknowledge TUN SYN")
		}
	}
entered:
	for {
		select {
		case packet := <-system.output:
			if len(packet) < 40 || packet[9] != 6 || binary.BigEndian.Uint16(packet[22:24]) != sourcePort {
				continue
			}
			ipLength := int(packet[0]&15) * 4
			tcpLength := int(packet[ipLength+12]>>4) * 4
			if len(packet) != ipLength+tcpLength {
				t.Fatal("certificate-rejected client received successful target bytes")
			}
			if packet[33]&5 != 0 {
				return // FIN/RST is supplementary; the real TLS error is asserted below.
			}
		case <-deadline:
			t.Fatal("certificate-rejected TUN request did not terminate")
		}
	}
}

func TestClientTUNFullSourceNodeTLSRejectsCertificatesAndRecoversOriginalPolicy(t *testing.T) {
	// CA state belongs only to this serial test process, never the OS trust store.
	trustedRoot, trustedKey := sourceTLSRoot(t)
	untrustedRoot, untrustedKey := sourceTLSRoot(t)
	oldSystem, oldEmbed := ca.DisableSystemCa, ca.DisableEmbedCa
	ca.DisableSystemCa, ca.DisableEmbedCa = true, true
	ca.ResetCertificate()
	t.Cleanup(func() { ca.DisableSystemCa, ca.DisableEmbedCa = oldSystem, oldEmbed; ca.ResetCertificate() })
	if err := ca.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRoot.Raw}))); err != nil {
		t.Fatal(err)
	}
	validCert, validDER := sourceTLSCertificate(t, trustedRoot, trustedKey, sourceTLSName)
	authorityCert, authorityDER := sourceTLSCertificate(t, untrustedRoot, untrustedKey, sourceTLSName)
	nameCert, nameDER := sourceTLSCertificate(t, trustedRoot, trustedKey, "other.example.invalid")
	valid := newSourceTLSPeer(t, validCert, validDER)
	authority := newSourceTLSPeer(t, authorityCert, authorityDER)
	wrongName := newSourceTLSPeer(t, nameCert, nameDER)
	dnsPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var physicalQuestions atomic.Int32
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buffer := make([]byte, 2048)
		for {
			n, address, err := dnsPeer.ReadFrom(buffer)
			if err != nil {
				return
			}
			physicalQuestions.Add(1)
			question := new(D.Msg)
			if question.Unpack(buffer[:n]) != nil {
				return
			}
			answer := new(D.Msg).SetRcode(question, D.RcodeNameError)
			encoded, err := answer.Pack()
			if err != nil {
				return
			}
			if _, err = dnsPeer.WriteTo(encoded, address); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { dnsPeer.Close(); <-dnsDone })
	nameserver := dnsPeer.LocalAddr().String()
	trustConfig := []byte(fmt.Sprintf("tls:\n  custom-certifactes: [%q]\n", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRoot.Raw}))))
	original := append(sourceTLSInput(valid, nameserver), trustConfig...)
	root := t.TempDir()
	owner, err := policyowner.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	var originalCandidate, coreInstance string
	var previousGeneration uint64
	for index, round := range []struct {
		name      string
		peer      *sourceTLSPeer
		errorText string
	}{
		{"normal", valid, ""},
		{"authority-rejected", authority, "unknown authority"},
		{"authority-recovered", valid, ""},
		{"name-rejected", wrongName, "not " + sourceTLSName},
		{"name-recovered", valid, ""},
	} {
		index, round := index, round // go1.20 range lifetime.
		if !t.Run(round.name, func(t *testing.T) {
			events := L.Subscribe()
			defer L.UnSubscribe(events)
			input := original
			if round.errorText != "" {
				input = append(sourceTLSInput(round.peer, nameserver), trustConfig...) // Only the node port differs.
			}
			var protects atomic.Int32
			manager, generation, system, started := startSourceTLS(t, owner, root, input, &protects)
			if generation <= previousGeneration {
				t.Fatal("recovery reused an old runtime generation")
			}
			previousGeneration = generation
			if coreInstance == "" {
				coreInstance = started.CoreInstance
			}
			if started.CoreInstance != coreInstance || coreInstance == "" {
				t.Fatal("TLS observations changed their actual core process identity")
			}
			if round.errorText == "" {
				if originalCandidate == "" {
					originalCandidate = started.CandidateDigest
				}
				if started.CandidateDigest != originalCandidate || !bytes.Equal(input, original) {
					t.Fatal("recovery changed original source, resource or selected-member context")
				}
			}
			host := fmt.Sprintf("fresh-%d.proxy-fixture.test", index)
			answer := clientDomainQuestion(t, system, host+".", D.TypeA, uint16(54500+index))
			if len(answer.Answer) != 1 {
				t.Fatal("fresh source-policy hostname did not return one fake-IP")
			}
			address := answer.Answer[0].(*D.A).A
			failureEvent := "not-applicable-on-success"
			if round.errorText == "" {
				domainTCPExchange(t, system, address, 443, uint16(54600+index), sourceTLSRequest, sourceTLSResponse)
			} else {
				rejectedSourceTLSRequest(t, system, address, uint16(54600+index))
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				for failureEvent == "not-applicable-on-success" {
					select {
					case event := <-events:
						if strings.Contains(event.Payload, round.errorText) {
							failureEvent = event.Payload
						}
					case <-deadline.C:
						t.Fatal("actual TLS rejection had no original error log")
					}
				}
			}
			select {
			case handshake := <-round.peer.handshakes:
				if handshake.sni != sourceTLSName || !handshake.certificateSent || (handshake.err == nil) != (round.errorText == "") {
					t.Fatalf("peer did not send the specified certificate under the original SNI: %+v", handshake)
				}
			case <-time.After(time.Second):
				t.Fatal("actual TLS peer did not finish its certificate exchange")
			}
			observed := manager.Query(generation, 1)
			if protects.Load() == 0 {
				t.Fatal("actual node TLS did not pass the physical-socket protection boundary")
			}
			if physicalQuestions.Load() != 0 {
				t.Fatal("a fake-IP proxy request added an undeclared physical target lookup or direct route")
			}
			if observed.Phase != "running" || !observed.ForwardingActive || observed.CoreInstance != coreInstance || observed.Generation != generation || observed.CandidateDigest != started.CandidateDigest || observed.FailureCode != "" || observed.DNS == nil || len(observed.DNS.Queries) != 1 || !observed.DNS.Queries[0].FakeIP || observed.DNS.Queries[0].QuestionDigest != domainHash(host) {
				t.Fatalf("request outcome replaced truthful service/DNS identity: %+v", observed)
			}
			if round.errorText == "" {
				if len(observed.Connections) != 1 {
					t.Fatal("successful source-policy TLS flow lacks its actual rule observation")
				}
				connection := observed.Connections[0]
				if connection.Rule != "RuleSet" || connection.Node != "source-tls-node" || connection.Upload == 0 || connection.Download == 0 || connection.Attribution == nil || connection.Attribution.DomainDigest != domainHash(host) || connection.Attribution.RulePayloadDigest != domainHash("D1Routes") || connection.Attribution.DNSSequence != 1 {
					t.Fatalf("TLS request escaped the original source rule/preference: %+v", connection)
				}
			} else if round.peer.authenticated.Load() != 0 || round.peer.targetBytes.Load() != 0 || len(observed.Connections) != 0 {
				t.Fatal("certificate rejection admitted Trojan authentication or target bytes")
			}
			assertTrojanStopped(t, manager, generation, system)
			stopped := manager.Query(generation, 1)
			if owner.ResourceAcquireCount() != "0" {
				t.Fatal("fixed original resources were unexpectedly reacquired")
			}
			select {
			case err := <-round.peer.closed:
				if round.errorText == "" && !errors.Is(err, io.EOF) {
					t.Fatalf("normal Stop did not close the real TLS socket with EOF: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("normal Stop did not join the real TLS peer")
			}
			t.Logf("D1_TLS_ROUND name=%s core=%s generation=%d input=%s candidate=%s actualFailureEvent=%s certificateSent=true sniPreserved=true normalStop=complete", round.name, coreInstance, generation, observed.InputDigest, observed.CandidateDigest, failureEvent)
			for _, snapshot := range []R.Receipt{observed, stopped} {
				encoded, err := json.Marshal(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("D1_TLS_RUNTIME_RECEIPT:%s", encoded)
			}
		}) {
			break
		}
	}
}
