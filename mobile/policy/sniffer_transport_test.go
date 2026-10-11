package policy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/tunnel"
	quic "github.com/metacubex/quic-go"
	metaTLS "github.com/metacubex/tls"
)

func preparedPublicSniffer(t *testing.T, raw []byte) (*policy.Engine, *config.Config) {
	t.Helper()
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	baseline := engine.ResourceAcquireCount()
	plan := engine.Plan("sniffer-transport-plan", raw, nil)
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := engine.Validate("sniffer-transport-validate", raw, prepared); plan.Category != "planned" || receipt.Category != "pass" {
		t.Fatalf("original transport sniffer preparation failed: %s/%s", plan.Code, receipt.Code)
	}
	candidate, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { discardUnpublishedPublicSniffer(t, candidate) })
	if engine.ResourceAcquireCount() != baseline {
		t.Fatal("sniffer preparation acquired a resource")
	}
	return engine, candidate
}

func discardUnpublishedPublicSniffer(t *testing.T, candidate *config.Config) {
	t.Helper()
	// Actual publication transfers cleanup to the executor. Its registered
	// cleanup checks RetireConfig; this fallback only owns untransferred builds.
	if err := candidate.Discard(context.Background()); err != nil && !errors.Is(err, configresources.ErrTransferred) {
		t.Error(err)
	}
}

func TestOriginalSnifferRoutesActualTLSClientHelloThroughOwnedTCP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("public-sniff-answer")) }))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	engine, cfg := preparedPublicSniffer(t, []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nsniffer:\n enable: true\n parse-pure-ip: true\n override-destination: false\n sniff: {TLS: {ports: [%d]}}\nrules: ['DOMAIN,example.com,DIRECT', 'MATCH,REJECT']\n", port)))
	baseline := engine.ResourceAcquireCount()
	var protected atomic.Int32
	_, generation := activatePublicPolicy(t, cfg, []string{"127.0.0.1"}, &protected)
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	client, inbound := net.Pipe()
	metadata := &C.Metadata{Type: C.TUN, NetWork: C.TCP, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: 43215, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(port)}
	done := make(chan struct{})
	go func() { defer close(done); bound.HandleTCPConn(inbound, metadata) }()
	t.Cleanup(func() { _ = client.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	secure := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
	_ = secure.SetDeadline(time.Now().Add(3 * time.Second))
	if err = secure.Handshake(); err != nil {
		t.Fatal("actual trusted TLS ClientHello failed through original sniffer", err)
	}
	if _, err = io.WriteString(secure, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(secure)
	if err != nil || !containsPublicAnswer(answer) || metadata.SniffHost != "example.com" || metadata.Host != "" || metadata.DstIP.String() != "127.0.0.1" || protected.Load() == 0 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("original TLS SNI routing or override=false semantics changed", err)
	}
	_ = client.Close()
}

type publicQUICPacket struct {
	data      []byte
	drops     atomic.Int32
	completed chan error
}

func (p *publicQUICPacket) Data() []byte { return p.data }
func (p *publicQUICPacket) Drop()        { p.drops.Add(1) }
func (*publicQUICPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 111, 0, 1), Port: 43216}
}
func (*publicQUICPacket) WriteBack(data []byte, _ net.Addr) (int, error) { return len(data), nil }
func (p *publicQUICPacket) RetainUDPFlow() (func(), func(error), bool) {
	return func() {}, func(err error) { p.completed <- err }, true
}

func actualPublicQUICInitial(t *testing.T) []byte {
	t.Helper()
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := quic.Dial(ctx, socket, peer.LocalAddr(), &metaTLS.Config{ServerName: "documentation.example", NextProtos: []string{"h3"}, CurvePreferences: []metaTLS.CurveID{metaTLS.X25519}}, &quic.Config{HandshakeIdleTimeout: time.Second})
		if conn != nil {
			_ = conn.CloseWithError(0, "public-fixture-complete")
		}
	}()
	defer func() { cancel(); _ = socket.Close(); <-done }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	n, _, err := peer.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

func TestOriginalSnifferRoutesActualQUICInitialAndStopJoinsNATSender(t *testing.T) {
	initial := actualPublicQUICInitial(t)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	port := peer.LocalAddr().(*net.UDPAddr).Port
	engine, cfg := preparedPublicSniffer(t, []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nsniffer:\n enable: true\n parse-pure-ip: true\n override-destination: false\n sniff: {QUIC: {ports: [%d]}}\nrules: ['DOMAIN,documentation.example,DIRECT', 'MATCH,REJECT']\n", port)))
	baseline := engine.ResourceAcquireCount()
	var protected atomic.Int32
	_, generation := activatePublicPolicy(t, cfg, []string{"127.0.0.1"}, &protected)
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	packet := &publicQUICPacket{data: initial, completed: make(chan error, 1)}
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: 43216, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(port)})
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, len(initial)+1)
	n, _, err := peer.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != string(initial) || protected.Load() == 0 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("actual QUIC Initial must match its original SNI rule and preserve packet bytes", err)
	}
	tunnel.CancelForwarding()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = tunnel.StopForwarding(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-packet.completed:
		if err != nil || packet.drops.Load() != 1 {
			t.Fatal("actual QUIC sniffer/NAT/packet owner did not close completely", err)
		}
	case <-ctx.Done():
		t.Fatal("actual QUIC sniffer flow outlived Stop")
	}
}

func TestOriginalSnifferStopJoinsIncompleteTCPInput(t *testing.T) {
	engine, cfg := preparedPublicSniffer(t, []byte("ipv6: false\ndns: {enable: false}\nsniffer:\n enable: true\n parse-pure-ip: true\n sniff: {HTTP: {ports: [80]}}\nrules: ['MATCH,REJECT']\n"))
	baseline := engine.ResourceAcquireCount()
	var protected atomic.Int32
	_, generation := activatePublicPolicy(t, cfg, []string{"127.0.0.1"}, &protected)
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	client, inbound := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		bound.HandleTCPConn(inbound, &C.Metadata{NetWork: C.TCP, SrcIP: netip.MustParseAddr("10.111.0.1"), SrcPort: 43217, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80})
	}()
	t.Cleanup(func() { _ = client.Close(); <-done })
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = io.WriteString(client, "GET /"); err != nil {
		t.Fatal("actual sniffer did not enter its pending read", err)
	}
	tunnel.CancelForwarding()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err = tunnel.StopForwarding(ctx); err != nil {
		t.Fatal("Stop did not join the actual pending sniffer read", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("TCP sniffing survived confirmed Stop")
	}
	if protected.Load() != 0 || engine.ResourceAcquireCount() != baseline {
		t.Fatal("incomplete canceled sniffing must not dial or acquire resources")
	}
}
