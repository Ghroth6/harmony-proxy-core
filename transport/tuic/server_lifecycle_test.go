package tuic

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	v4 "github.com/metacubex/mihomo/transport/tuic/v4"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func TestTUICSessionStopWaitsForAcceptedHandler(t *testing.T) {
	forwarding.Enable()
	if err := forwarding.Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	scope, _ := forwarding.Context(1)
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	server, err := NewServer(&ServerOption{Context: scope, AsyncTCP: true,
		TlsConfig:  &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		QuicConfig: &quic.Config{EnableDatagrams: true}, Tokens: [][32]byte{GenTKN("lifecycle")},
		AuthenticationTimeout: time.Second, MaxUdpRelayPacketSize: 1200,
		HandleTcpFn: func(conn net.Conn, _ socks5.Addr, _ ...inbound.Addition) error {
			close(entered)
			<-release
			return conn.Close()
		},
	}, p)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()
	_, finish, err := forwarding.AcquireConstruction(scope)
	if err != nil {
		t.Fatal(err)
	}
	forwarding.Cleanup(scope, server.Close)
	finish()
	client := v4.NewClient(&v4.ClientOption{Token: GenTKN("lifecycle"), RequestTimeout: time.Second, MaxOpenStreams: 10}, false,
		func(ctx context.Context) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, p.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
		})
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "destination.test", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("TUIC handler not reached")
	}
	// The successful v4 response must precede the long-running relay; waiting
	// for it inside HandleTcpFn would deadlock the unchanged client contract.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	stopResult, closeResult := make(chan error, 1), make(chan error, 1)
	go func() { stopResult <- forwarding.Stop(stopCtx) }()
	// Listener.Close can race the scope's automatic Cleanup(server.Close).
	go func() { closeResult <- server.Close() }()
	err = <-stopResult
	stopCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop lost accepted handler: %v", err)
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("concurrent server Close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent server Close did not return")
	}
	close(release)
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.Prepare(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
