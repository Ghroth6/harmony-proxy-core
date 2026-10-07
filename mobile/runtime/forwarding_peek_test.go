//go:build with_gvisor

package runtime_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"github.com/metacubex/mihomo/tunnel"
)

// The external connection deliberately returns from Close before its in-flight
// Read completes. Closing a descriptor is not evidence that its user has joined.
type delayedReadConnection struct {
	reading, closed, release chan struct{}
	readOnce, closeOnce      sync.Once
}

func (c *delayedReadConnection) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.reading) })
	<-c.release
	return 0, io.ErrClosedPipe
}
func (c *delayedReadConnection) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *delayedReadConnection) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*delayedReadConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}
}
func (*delayedReadConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 51500}
}
func (*delayedReadConnection) SetDeadline(time.Time) error      { return nil }
func (*delayedReadConnection) SetReadDeadline(time.Time) error  { return nil }
func (*delayedReadConnection) SetWriteDeadline(time.Time) error { return nil }

func TestFailedActualProxyDialRetainsPeekReaderUntilItReturns(t *testing.T) {
	generation := nextGeneration()
	conn := &delayedReadConnection{reading: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	protected := make(chan struct{}, 1)
	register(generation, func(uint64, uint64, uintptr) int32 {
		<-conn.reading // Ensure the actual peek has entered its external Read.
		protected <- struct{}{}
		return protection.PlatformFailure
	})
	system := newPacketDescriptors()
	manager := R.NewManager(system, &productionGate)
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(conn.release) })
		if result := manager.Stop(generation); result.Cleanup != "complete" {
			t.Errorf("real runtime cleanup: %+v", result)
		}
	})
	if result := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1)); result.Outcome != "running" {
		t.Fatalf("real candidate/start: %+v", result)
	}
	bound, err := tunnel.BoundForwardingTunnel(generation)
	if err != nil {
		t.Fatal(err)
	}
	caller, cancelDial := context.WithCancel(context.Background())
	defer cancelDial()
	done := make(chan struct{})
	go func() {
		defer close(done)
		bound.HandleTCPConn(conn, &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443, RequestContext: caller})
	}()
	select {
	case <-protected:
		cancelDial() // Cancel retry only after the real protected dial failed.
	case <-time.After(time.Second):
		t.Fatal("actual physical dial bypassed the generation protection gate")
	}
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("failed protected dial did not close inbound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = tunnel.StopForwarding(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forwarding finished while its peek Read was still pending: %v", err)
	}
	select {
	case <-done:
		t.Fatal("entry callback returned before its peek reader")
	default:
	}
	releaseOnce.Do(func() { close(conn.release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader returned but callback did not join")
	}
	if stopped := manager.Stop(generation); stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("joined reader not reflected in actual stop: %+v", stopped)
	}
}
