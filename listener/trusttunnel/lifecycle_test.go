package trusttunnel

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/metacubex/mihomo/component/ca"
	LC "github.com/metacubex/mihomo/listener/config"
)

type recordedListenConfig struct {
	tcp net.Listener
	udp net.PacketConn
}

var errTestRawSocket = errors.New("injected QUIC socket setup failure")

type failedRawPacket struct{ net.PacketConn }

func (c *failedRawPacket) SyscallConn() (syscall.RawConn, error) { return nil, errTestRawSocket }

func (c *recordedListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := (&net.ListenConfig{}).Listen(ctx, network, address)
	c.tcp = l
	return l, err
}
func (c *recordedListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	l, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	c.udp = l
	if err != nil {
		return nil, err
	}
	return &failedRawPacket{l}, nil
}

func TestListenerLifecycleTrustTunnelPartialServiceStart(t *testing.T) {
	lc := &recordedListenConfig{}
	certificate, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	// TCP HTTP starts first; QUIC then fails while accessing its socket. The
	// partially started service and both actual listeners must be rolled back.
	l, err := New(LC.TrustTunnelServer{Listen: "127.0.0.1:0", Certificate: certificate, PrivateKey: key, Network: []string{"tcp", "udp"}}, lc, nil)
	if l != nil {
		defer l.Close()
	}
	if !errors.Is(err, errTestRawSocket) || l != nil {
		t.Fatalf("constructor = %v, %v", l, err)
	}
	if lc.tcp == nil || lc.udp == nil {
		t.Fatal("did not reach partial service startup")
	}
	tcp, err := net.Listen("tcp", lc.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", lc.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
}

type retryListener struct {
	net.Listener
	failure error
	calls   int
}

func (l *retryListener) Close() error {
	l.calls++
	if l.calls == 1 {
		return l.failure
	}
	return l.Listener.Close()
}
func TestListenerLifecycleTrustTunnelCloseRetry(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	failure := errors.New("injected close failure")
	owned := &retryListener{Listener: tcp, failure: failure}
	l := &Listener{listeners: []net.Listener{owned}}
	if err = l.Close(); !errors.Is(err, failure) {
		t.Fatalf("close = %v", err)
	}
	if len(l.listeners) != 1 {
		t.Fatal("lost failed close owner")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if len(l.listeners) != 0 || owned.calls != 2 {
		t.Fatal("retry did not retire the listener")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
}
