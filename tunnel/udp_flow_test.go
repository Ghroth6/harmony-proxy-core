package tunnel_test

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// This is the caller's public incoming packet and completion receipt, not a
// replacement NAT table, adapter, dialer or physical connection.
type flowPacket struct {
	drops     atomic.Int32
	retained  atomic.Int32
	closing   atomic.Bool
	completed chan error
	write     func([]byte, net.Addr) (int, error)
}

func (*flowPacket) Data() []byte { return []byte("client-udp-buffer") }
func (*flowPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 51341}
}
func (p *flowPacket) WriteBack(data []byte, addr net.Addr) (int, error) {
	if p.write != nil {
		return p.write(data, addr)
	}
	return 0, errors.New("disabled UDP unexpectedly wrote a reply")
}

func TestBoundUDPFlowWaitsForActualReadWorkerBeforeCompletion(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	bound, _, _ := originalUDPPolicyRun(t, "MATCH,DIRECT", true)
	writeEntered := make(chan string, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var writeReturned atomic.Bool
	packet := &flowPacket{completed: make(chan error, 2)}
	packet.write = func(data []byte, addr net.Addr) (int, error) {
		if addr.String() != peer.LocalAddr().String() {
			return 0, errors.New("original reply source was changed")
		}
		writeEntered <- string(data)
		<-release
		writeReturned.Store(true)
		return len(data), nil
	}
	peerAddr := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: netip.MustParseAddr("10.111.0.2"), SrcPort: 51341, DstIP: peerAddr.Addr(), DstPort: peerAddr.Port(), SpecialProxy: "DIRECT"})
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, source, err := peer.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "client-udp-buffer" {
		t.Fatalf("real direct UDP peer did not receive the client packet: n=%d err=%v", n, err)
	}
	if _, err = peer.WriteTo([]byte("return-from-real-peer"), source); err != nil {
		t.Fatal(err)
	}
	if reply := await(t, writeEntered); reply != "return-from-real-peer" {
		t.Fatal("real peer response did not enter caller writeback")
	}
	tunnel.CancelForwarding()
	select {
	case <-packet.completed:
		t.Fatal("flow capacity was released while its actual read worker still owned writeback")
	case <-time.After(75 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	stopRun(t)
	if err := await(t, packet.completed); err != nil || !writeReturned.Load() || !packet.closing.Load() || packet.retained.Load() != 1 || packet.drops.Load() != 1 {
		t.Fatalf("actual worker/close completion was not retained: err=%v writeReturned=%v retained=%d drops=%d", err, writeReturned.Load(), packet.retained.Load(), packet.drops.Load())
	}
}
func (p *flowPacket) Drop() { p.drops.Add(1) }
func (p *flowPacket) RetainUDPFlow() (func(), func(error), bool) {
	p.retained.Add(1)
	return func() { p.closing.Store(true) }, func(err error) { p.completed <- err }, true
}

type deniedFlowPacket struct{ *flowPacket }

func (p *deniedFlowPacket) RetainUDPFlow() (func(), func(error), bool) {
	p.retained.Add(1)
	return nil, nil, false
}

func TestBoundUDPDeniedFlowCannotOpenANewPhysicalSocket(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	bound, _, _ := originalUDPPolicyRun(t, "MATCH,DIRECT", true)
	packet := &deniedFlowPacket{&flowPacket{completed: make(chan error, 2)}}
	peerAddr := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: netip.MustParseAddr("10.111.0.2"), SrcPort: 51341, DstIP: peerAddr.Addr(), DstPort: peerAddr.Port(), SpecialProxy: "DIRECT"})
	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := peer.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("closing source flow created a fresh real physical UDP socket")
	}
	stopRun(t)
	if packet.retained.Load() != 1 || packet.drops.Load() != 1 {
		t.Fatalf("denied caller lease did not settle its individual buffer: retained=%d drops=%d", packet.retained.Load(), packet.drops.Load())
	}
}

func TestBoundUDPRejectedRouteReleasesFlowAfterBufferDrop(t *testing.T) {
	bound, _, _ := originalUDPPolicyRun(t, "MATCH,REJECT", true)
	packet := &flowPacket{completed: make(chan error, 2)}
	bound.HandleUDPPacket(packet, &C.Metadata{Type: C.TUN, NetWork: C.UDP, SrcIP: netip.MustParseAddr("10.111.0.2"), SrcPort: 51341, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 3478, SpecialProxy: "unavailable"})
	select {
	case err := <-packet.completed:
		if err != nil || !packet.closing.Load() || packet.retained.Load() != 1 || packet.drops.Load() != 1 {
			t.Fatalf("candidate failure did not settle caller ownership: complete=%v closing=%v retained=%d drops=%d", err, packet.closing.Load(), packet.retained.Load(), packet.drops.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("candidate failure lost caller flow completion: retained=%d drops=%d", packet.retained.Load(), packet.drops.Load())
	}
	stopRun(t)
	select {
	case <-packet.completed:
		t.Fatal("flow completed twice")
	default:
	}
}
