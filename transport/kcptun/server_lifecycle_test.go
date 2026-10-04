package kcptun

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
)

func TestKcpTunSessionStopWaitsForAcceptedHandler(t *testing.T) {
	forwarding.Enable()
	if err := forwarding.Start(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	scope, _ := forwarding.Context(1)
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	config := Config{NoComp: true}
	server := NewServerContext(scope, config)
	go server.Serve(p, func(conn net.Conn) { close(entered); <-release; _ = conn.Close() })
	_, finish, err := forwarding.AcquireConstruction(scope)
	if err != nil {
		t.Fatal(err)
	}
	forwarding.Cleanup(scope, server.Close)
	finish()
	client := NewClient(config)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		return pc, p.LocalAddr(), err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("session")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("KcpTun handler not reached")
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
