package kcptun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

type slowClosePacket struct {
	net.PacketConn
	started chan struct{}
	release chan struct{}
	err     error
	calls   atomic.Int32
}

func (p *slowClosePacket) Close() error {
	if p.calls.Add(1) == 1 {
		close(p.started)
	}
	<-p.release
	return errors.Join(p.PacketConn.Close(), p.err)
}

func TestKcpTunFailedSessionIsClosedWithoutBlockingReplacement(t *testing.T) {
	testKcpTunSessionCleanup(t, false)
}

func TestKcpTunExpiredSessionRetainsCleanupErrorWithoutBlockingReplacement(t *testing.T) {
	testKcpTunSessionCleanup(t, true)
}

func testKcpTunSessionCleanup(t *testing.T, expired bool) {
	t.Helper()
	serverPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverPacket.Close()
	server := NewServer(Config{NoComp: true})
	defer server.Close()
	go server.Serve(serverPacket, func(conn net.Conn) { _, _ = io.Copy(conn, conn); _ = conn.Close() })
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	wantClose := errors.New("controlled packet close failure")
	old := &slowClosePacket{PacketConn: packet, started: make(chan struct{}), release: make(chan struct{}), err: wantClose}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(old.release) }) }
	config := Config{NoComp: true}
	if expired {
		config.AutoExpire, config.ScavengeTTL = 1, 1
	}
	client := NewClient(config)
	t.Cleanup(func() { release(); _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	first, err := client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		return old, serverPacket.LocalAddr(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		// Exercise the existing real expiry timer, not a private cleanup hook.
		select {
		case <-old.started:
		case <-ctx.Done():
			t.Fatal("expired session cleanup did not start")
		}
	} else {
		// A real UDP read error makes smux.IsClosed true without closing its
		// transport. Observe it through the stream before requesting reuse.
		if err := packet.SetReadDeadline(time.Now()); err != nil {
			t.Fatal(err)
		}
		_ = first.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := first.Read(make([]byte, 1)); err == nil {
			t.Fatal("packet error did not reach the stream")
		}
	}
	second, err := client.OpenStream(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp", "127.0.0.1:0")
		return p, serverPacket.LocalAddr(), e
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetDeadline(time.Now().Add(time.Second))
	if _, err := second.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 3)
	if _, err := io.ReadFull(second, reply); err != nil || string(reply) != "new" {
		t.Fatalf("replacement transport: %q, %v", reply, err)
	}
	select {
	case <-old.started:
	case <-ctx.Done():
		t.Fatal("failed session was forgotten without closing its UDP socket")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("client Close returned before packet cleanup: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case err := <-closed:
		if !errors.Is(err, wantClose) {
			t.Fatalf("lost packet cleanup error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client Close did not join released cleanup")
	}
	if err := client.Close(); !errors.Is(err, wantClose) || old.calls.Load() != 1 {
		t.Fatalf("repeated Close lost result or repeated cleanup: %v, calls=%d", err, old.calls.Load())
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
