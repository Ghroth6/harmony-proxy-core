package kcptun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/smux"
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

func TestKcpTunServerCloseReleasesUnreadMuxStreams(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, noComp := range []bool{true, false} {
			t.Run(fmt.Sprintf("v%d/no-comp=%t", version, noComp), func(t *testing.T) {
				p, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				config := Config{NoComp: noComp, SmuxVer: version, SmuxBuf: 64, StreamBuf: 64, FrameSize: 256}
				server := NewServer(config)
				defer server.Close()
				accepted := make(chan net.Conn, 1)
				go server.Serve(p, func(conn net.Conn) {
					// Read one byte to prove the real payload arrived; leave more
					// than the receive budget unread, without closing the stream.
					_, _ = io.ReadFull(conn, make([]byte, 1))
					accepted <- conn
				})
				client := NewClient(config)
				defer client.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				stream, err := client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
					pc, err := net.ListenPacket("udp", "127.0.0.1:0")
					return pc, p.LocalAddr(), err
				})
				if err != nil {
					t.Fatal(err)
				}
				_ = stream.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := stream.Write(make([]byte, 128)); err != nil {
					t.Fatal(err)
				}
				var received *smux.Stream
				select {
				case conn := <-accepted:
					received = conn.(*smux.Stream)
					defer received.Close()
				case <-ctx.Done():
					t.Fatal("server payload was not received")
				}
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-received.GetDieCh():
				case <-ctx.Done():
					t.Fatal("server Close left an unread smux stream alive")
				}
				if err := server.Close(); err != nil {
					t.Fatalf("repeated server Close: %v", err)
				}
			})
		}
	}
}
