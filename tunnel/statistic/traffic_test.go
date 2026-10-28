package statistic

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

// Socket-boundary fixtures for the retained public accounting contract.
type accountingConn struct {
	C.Conn
	n           int
	err         error
	bufferRead  func(*buf.Buffer) error
	bufferWrite func(*buf.Buffer) error
}

func (*accountingConn) ProviderChains() C.Chain           { return nil }
func (*accountingConn) RemoteDestination() string         { return "test:443" }
func (*accountingConn) Close() error                      { return nil }
func (c *accountingConn) Read([]byte) (int, error)        { return c.n, c.err }
func (c *accountingConn) Write([]byte) (int, error)       { return c.n, c.err }
func (c *accountingConn) ReadBuffer(b *buf.Buffer) error  { return c.bufferRead(b) }
func (c *accountingConn) WriteBuffer(b *buf.Buffer) error { return c.bufferWrite(b) }

type accountingPacketConn struct {
	C.PacketConn
	n   int
	err error
}

func (*accountingPacketConn) ProviderChains() C.Chain   { return nil }
func (*accountingPacketConn) RemoteDestination() string { return "test:53" }
func (*accountingPacketConn) Close() error              { return nil }
func (c *accountingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return c.n, &net.UDPAddr{}, c.err
}
func (c *accountingPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return make([]byte, c.n), nil, &net.UDPAddr{}, c.err
}
func (c *accountingPacketConn) WriteTo([]byte, net.Addr) (int, error) { return c.n, c.err }

type trafficConn struct {
	accountingConn
	kind C.AdapterType
	name string
}

func (c *trafficConn) EgressType() C.AdapterType { return c.kind }
func (c *trafficConn) Chains() C.Chain           { return C.Chain{c.name, "selected-group"} }

type trafficPacketConn struct {
	accountingPacketConn
	kind C.AdapterType
	name string
}

func (c *trafficPacketConn) EgressType() C.AdapterType { return c.kind }
func (c *trafficPacketConn) Chains() C.Chain           { return C.Chain{c.name, "selected-group"} }

func TestUpstreamTotalIncludesDirectAndProxyAfterClose(t *testing.T) {
	m := &Manager{}
	for _, kind := range []C.AdapterType{C.Direct, C.Socks5} {
		tcp := NewTCPTracker(&trafficConn{kind: kind, accountingConn: accountingConn{n: 3, err: io.EOF}}, m, &C.Metadata{}, nil, 5, 7, true)
		if n, err := tcp.Read(nil); n != 3 || err != io.EOF {
			t.Fatal("partial read changed")
		}
		udp := NewUDPTracker(&trafficPacketConn{kind: kind, accountingPacketConn: accountingPacketConn{n: 2}}, m, &C.Metadata{}, nil, 11, 13, true)
		_, _ = udp.WriteTo(nil, &net.UDPAddr{})
		_ = tcp.Close()
		_ = udp.Close()
	}
	if up, down := m.Total(); up != 36 || down != 46 {
		t.Fatalf("all traffic = %d/%d", up, down)
	}
	if len(m.Snapshot().Connections) != 0 {
		t.Fatal("closed connections retained as active")
	}
}

func TestUpstreamResetKeepsLiveConnectionTotals(t *testing.T) {
	m := &Manager{}
	tracker := NewTCPTracker(&trafficConn{kind: C.Socks5, accountingConn: accountingConn{n: 7}}, m, &C.Metadata{}, nil, 3, 5, true)
	defer tracker.Close()
	m.ResetStatistic()
	if up, down := m.Total(); up != 0 || down != 0 {
		t.Fatal("reset did not clear total")
	}
	if up, down := m.Now(); up != 0 || down != 0 {
		t.Fatal("reset did not clear rate")
	}
	if m.Get(tracker.ID()) != tracker || tracker.Info().UploadTotal.Load() != 3 || tracker.Info().DownloadTotal.Load() != 5 {
		t.Fatal("reset changed connection")
	}
	_, _ = tracker.Write(nil)
	if up, down := m.Total(); up != 7 || down != 0 {
		t.Fatal("post-reset accounting changed")
	}
}

func TestUpstreamConcurrentTrackerAccounting(t *testing.T) {
	m := &Manager{}
	tracker := NewTCPTracker(&trafficConn{kind: C.Socks5, accountingConn: accountingConn{n: 1}}, m, &C.Metadata{}, nil, 0, 0, true)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				_, _ = tracker.Read(nil)
				_, _ = tracker.Write(nil)
				m.Total()
			}
		}()
	}
	workers.Wait()
	_ = tracker.Close()
	if up, down := m.Total(); up != 8000 || down != 8000 {
		t.Fatalf("lost traffic %d/%d", up, down)
	}
}
