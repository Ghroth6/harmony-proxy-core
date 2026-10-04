package tuic

import (
	"context"
	"errors"
	"net"
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
