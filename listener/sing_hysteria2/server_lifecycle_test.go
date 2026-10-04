package sing_hysteria2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type lifecycleTunnel struct{ ctx context.Context }

func (t lifecycleTunnel) BindContext(ctx context.Context) context.Context {
	return forwarding.Bind(ctx, t.ctx)
}
func (lifecycleTunnel) HandleTCPConn(c net.Conn, _ *C.Metadata)      { _ = c.Close() }
func (lifecycleTunnel) HandleUDPPacket(p C.UDPPacket, _ *C.Metadata) { p.Drop() }
func (lifecycleTunnel) NatTable() C.NatTable                         { return nil }

func TestHysteria2StopJoinsUnauthenticatedQUICSessions(t *testing.T) {
	forwarding.Enable()
	if err := forwarding.Prepare(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	scope, _ := forwarding.Context(1)
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := New(LC.Hysteria2Server{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key, Users: map[string]string{"test": "password"}}, &net.ListenConfig{}, lifecycleTunnel{scope})
	if err != nil {
		t.Fatal(err)
	}
	preparedCtx, preparedCancel := context.WithTimeout(context.Background(), time.Second)
	preparedConn, preparedErr := quic.DialAddr(preparedCtx, listener.AddrList()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	preparedCancel()
	if preparedErr == nil {
		_ = preparedConn.CloseWithError(0, "")
		t.Fatal("prepared listener admitted QUIC connection")
	}
	if err := forwarding.Activate(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.AddrList()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	// No Hysteria authentication request is sent. Service.Context alone does
	// not close this accepted connection in the pinned sing-quic dependency.
	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatalf("unauthed QUIC remained live: %v", err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("concurrent listener Close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent listener Close did not return")
	}
	if err := forwarding.Prepare(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(LC.Hysteria2Server{}, &net.ListenConfig{}, lifecycleTunnel{scope}); err == nil {
		t.Fatal("stopped generation admitted another constructor")
	}
}
