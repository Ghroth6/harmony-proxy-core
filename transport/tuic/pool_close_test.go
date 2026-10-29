package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type closeErrorClient struct {
	err    error
	closes atomic.Int32
}

func (*closeErrorClient) DialContext(context.Context, *C.Metadata) (net.Conn, error) {
	panic("not a dial test")
}
func (*closeErrorClient) ListenPacket(context.Context, *C.Metadata) (net.PacketConn, error) {
	panic("not a packet test")
}
func (*closeErrorClient) OpenStreams() int64       { return 1 }
func (*closeErrorClient) LastVisited() time.Time   { return time.Now() }
func (*closeErrorClient) SetLastVisited(time.Time) {}
func (c *closeErrorClient) Close() error           { c.closes.Add(1); return c.err }

func TestTUICPoolCloseRetainsAllClientErrors(t *testing.T) {
	firstErr, secondErr := errors.New("first close failed"), errors.New("second close failed")
	first, second := &closeErrorClient{err: firstErr}, &closeErrorClient{err: secondErr}
	pool := NewPoolClientV5(&ClientOptionV5{}, nil)
	pool.tcpClients.PushBack(first)
	pool.udpClients.PushBack(second)
	for i := 0; i < 2; i++ {
		err := pool.Close()
		if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
			t.Fatalf("lost cleanup result: %v", err)
		}
	}
	if first.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatal("opaque client close was repeated")
	}
}

// Control only the protocol boundary. Exercise admission and shutdown through
// the public pool operations, including a slow old client's actual Close.
type poolProgressClient struct {
	closeErrorClient
	lastVisited time.Time
	dial        func(context.Context) (net.Conn, error)
	packet      func(context.Context) (net.PacketConn, error)
	close       func() error
}

func (c *poolProgressClient) DialContext(ctx context.Context, _ *C.Metadata) (net.Conn, error) {
	return c.dial(ctx)
}
func (c *poolProgressClient) ListenPacket(ctx context.Context, _ *C.Metadata) (net.PacketConn, error) {
	return c.packet(ctx)
}
func (*poolProgressClient) OpenStreams() int64             { return 0 }
func (c *poolProgressClient) LastVisited() time.Time       { return c.lastVisited }
func (c *poolProgressClient) SetLastVisited(now time.Time) { c.lastVisited = now }
func (c *poolProgressClient) Close() error {
	c.closes.Add(1)
	if c.close != nil {
		return c.close()
	}
	return c.err
}

func TestTUICIdleCleanupDoesNotBlockOtherRequestsOrStopCancellation(t *testing.T) {
	for _, stopping := range []bool{false, true} {
		name := "other-request"
		if stopping {
			name = "stop-cancellation"
		}
		t.Run(name, func(t *testing.T) {
			pool := NewPoolClientV5(&ClientOptionV5{}, nil)
			cleanupStarted, cleanupRelease := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(cleanupRelease) }) }
			wantCleanup := errors.New("old idle client cleanup failed")
			old := &poolProgressClient{lastVisited: time.Now().Add(-time.Hour), close: func() error {
				close(cleanupStarted)
				<-cleanupRelease
				return wantCleanup
			}}
			wantDial := errors.New("controlled healthy client dial")
			healthy := &poolProgressClient{dial: func(context.Context) (net.Conn, error) { return nil, wantDial }}
			packetStarted := make(chan struct{})
			wantPacket := errors.New("controlled packet result")
			packet := &poolProgressClient{packet: func(ctx context.Context) (net.PacketConn, error) {
				close(packetStarted)
				if stopping {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, wantPacket
			}}
			pool.tcpClients.PushBack(healthy)
			pool.tcpClients.PushBack(old)
			pool.udpClients.PushBack(packet)
			t.Cleanup(func() { release(); _ = pool.Close() })
			waitSignal := func(signal <-chan struct{}, message string) {
				t.Helper()
				select {
				case <-signal:
				case <-time.After(time.Second):
					t.Fatal(message)
				}
			}
			result := func(done <-chan error, message string) error {
				t.Helper()
				select {
				case err := <-done:
					return err
				case <-time.After(time.Second):
					t.Fatal(message)
					return nil
				}
			}
			packetDone := make(chan error, 1)
			startPacket := func() {
				go func() { _, err := pool.ListenPacket(context.Background(), &C.Metadata{}); packetDone <- err }()
			}
			if stopping {
				startPacket()
				waitSignal(packetStarted, "initial packet request did not start")
			}
			dialDone := make(chan error, 1)
			go func() { _, err := pool.DialContext(context.Background(), &C.Metadata{}); dialDone <- err }()
			waitSignal(cleanupStarted, "old idle client cleanup did not start")
			closeDone := make(chan error, 1)
			if stopping {
				go func() { closeDone <- pool.Close() }()
				if err := result(packetDone, "idle cleanup blocked cancellation of an admitted request"); !errors.Is(err, context.Canceled) {
					t.Fatalf("packet result = %v", err)
				}
				select {
				case err := <-closeDone:
					t.Fatalf("Close finished before old cleanup returned: %v", err)
				default:
				}
			} else {
				startPacket()
				if err := result(packetDone, "idle cleanup blocked an unrelated packet request"); !errors.Is(err, wantPacket) {
					t.Fatalf("packet result = %v", err)
				}
				if err := result(dialDone, "idle cleanup blocked the selected healthy client"); !errors.Is(err, wantDial) {
					t.Fatalf("dial result = %v", err)
				}
			}
			release()
			if !stopping {
				go func() { closeDone <- pool.Close() }()
			}
			if err := result(closeDone, "pool cleanup did not finish"); !errors.Is(err, wantCleanup) {
				t.Fatalf("Close lost the old cleanup failure: %v", err)
			}
			if stopping {
				_ = result(dialDone, "admitted dial did not finish")
			}
			if old.closes.Load() != 1 {
				t.Fatalf("old client closed %d times", old.closes.Load())
			}
		})
	}
}
