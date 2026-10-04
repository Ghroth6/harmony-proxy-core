package shadowquic

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-tls"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/transport/socks5"
)

func TestShadowQUICSessionStopWaitsForAcceptedHandler(t *testing.T) {
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
	server, err := NewServer(&ServerOption{Context: scope,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, QUICConfig: &quic.Config{EnableDatagrams: true},
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, p.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRequest(stream, CommandConnect, socks5.ParseAddr("destination.test:443")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("ShadowQUIC handler not reached")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = forwarding.Stop(stopCtx)
	stopCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop lost accepted handler: %v", err)
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
