package kcptun

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestKcpTunClientCloseReleasesNonExpiringPoolAndRejectsNewStreams(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	server := NewServer(Config{NoComp: true})
	defer server.Close()
	accepted := make(chan net.Conn, 1)
	go server.Serve(packet, func(conn net.Conn) { accepted <- conn; _, _ = io.Copy(io.Discard, conn); _ = conn.Close() })
	client := NewClient(Config{NoComp: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp", "127.0.0.1:0")
		return p, packet.LocalAddr(), e
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("server did not receive stream")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("late")); err == nil {
		t.Fatal("pooled stream survived client Close")
	}
	if _, err = client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		t.Fatal("dial after Close")
		return nil, nil, io.EOF
	}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed admission: %v", err)
	}
}

func TestKcpTunClientCloseCancelsInFlightPoolCreation(t *testing.T) {
	client := NewClient(Config{NoComp: true})
	entered, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			close(entered)
			<-ctx.Done()
			return nil, nil, ctx.Err()
		})
		finished <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited without cancelling constructor")
	}
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("constructor result: %v", err)
	}
}
