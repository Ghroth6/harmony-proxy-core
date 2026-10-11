package common_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type packetListener struct{ calls *atomic.Int32 }

func (p packetListener) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	p.calls.Add(1)
	return dialer.NewDialer().ListenPacket(ctx, network, address, remote)
}

func TestInternalQUICPathUsesRealProtectedPacketSocketWithoutCustomDialerBypass(t *testing.T) {
	denied := errors.New("synthetic platform protection denied")
	var calls, controls atomic.Int32
	var permitted atomic.Bool
	if err := dialer.InstallOutboundSocketPolicy(dialer.OutboundSocketPolicy{Required: func(context.Context) bool { return true }, Control: func(_ context.Context, _ string, _ string, raw syscall.RawConn) error {
		controls.Add(1)
		if raw == nil {
			t.Error("missing live physical socket")
		}
		if !permitted.Load() {
			return denied
		}
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	packet, connection, err := common.DialQuic(context.Background(), "127.0.0.1:443", nil, packetListener{&calls}, &tls.Config{ServerName: "tls.example", NextProtos: []string{"h3"}}, &quic.Config{}, common.DialQuicOption{})
	if packet != nil {
		packet.Close()
	}
	if connection != nil {
		connection.CloseWithError(0, "")
	}
	if !errors.Is(err, denied) || calls.Load() != 1 || controls.Load() != 1 {
		t.Fatal("authorized internal QUIC path must reach the real physical protection boundary before handshake")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated QUIC fixture"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	serverAccepted := make(chan bool, 1)
	go func() {
		defer close(serverDone)
		peer, acceptErr := listener.Accept(ctx)
		serverAccepted <- acceptErr == nil
		if peer != nil {
			<-ctx.Done()
			_ = peer.CloseWithError(0, "")
		}
	}()
	permitted.Store(true)
	packet, connection, err = common.DialQuic(ctx, listener.Addr().String(), nil, packetListener{&calls}, &tls.Config{ServerName: "127.0.0.1", RootCAs: roots, NextProtos: []string{"h3"}}, &quic.Config{}, common.DialQuicOption{})
	if err != nil || packet == nil || connection == nil || !connection.ConnectionState().TLS.HandshakeComplete || calls.Load() != 2 || controls.Load() != 2 {
		cancel()
		_ = listener.Close()
		<-serverDone
		t.Fatal("authorized internal path must complete real QUIC TLS through its protected physical socket")
	}
	if !<-serverAccepted {
		t.Error("real QUIC listener did not accept the protected client")
	}
	_ = connection.CloseWithError(0, "")
	if err := packet.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error("caller-owned packet close failed")
	}
	cancel()
	<-serverDone
}
