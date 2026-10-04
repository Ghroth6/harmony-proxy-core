package forwarding

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
)

func managementForTest(t *testing.T) {
	t.Helper()
	EnableManagementNetwork()
	t.Cleanup(func() {
		CancelManagementNetwork()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = WaitManagementNetwork(ctx)
		management.Lock()
		management.enabled, management.current = false, nil
		management.Unlock()
		dialer.SetNetworkLifecycle(nil)
	})
}

func TestManagementNetworkTransitionKeepsOriginalAttemptAndCommitOwner(t *testing.T) {
	managementForTest(t)
	ctx, finish, err := AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if Generation(ctx) != 0 {
		t.Fatal("management became forwarding")
	}
	CancelManagementNetwork()
	if _, _, err := AcquireManagementNetwork(context.Background()); !errors.Is(err, ErrManagementNetworkPaused) {
		t.Fatalf("admission: %v", err)
	}
	if err := ResumeManagementNetwork(); err == nil {
		t.Fatal("resumed before admitted work returned")
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait: %v", err)
	}
	committed := false
	if err := CommitManagementNetwork(ctx, func() error { committed = true; return nil }); err == nil || committed {
		t.Fatal("old commit accepted")
	}
	finish()
	if err := WaitManagementNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireManagementNetwork(context.WithoutCancel(ctx)); !errors.Is(err, ErrManagementNetworkPaused) {
		t.Fatalf("old detached attempt adopted new path: %v", err)
	}
	fresh, done, err := AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if err := CommitManagementNetwork(fresh, func() error { committed = true; return nil }); err != nil || !committed {
		t.Fatal("fresh path unavailable", err)
	}
}

func TestManagementNetworkOwnsRealTCPAndUDPSockets(t *testing.T) {
	managementForTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	conn, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-accepted
	defer peer.Close()
	packet, err := dialer.ListenPacket(context.Background(), "udp4", "127.0.0.1:0", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	// UDP syscall/OOB operations must remain available for QUIC after wrapping.
	if _, ok := packet.(interface{ SetReadBuffer(int) error }); !ok {
		t.Fatal("lost UDP socket methods")
	}
	CancelManagementNetwork()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := WaitManagementNetwork(wait); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("old")); err == nil {
		t.Fatal("old TCP still open")
	}
	if _, err := packet.WriteTo([]byte("old"), packet.LocalAddr()); err == nil {
		t.Fatal("old UDP still open")
	}
	if err := ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	fresh, err := dialer.ListenPacket(context.Background(), "udp4", "127.0.0.1:0", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.WriteTo([]byte("new"), fresh.LocalAddr()); err != nil {
		t.Fatal(err)
	}
}

type managementBlockedConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
	err     error
}

func (c *managementBlockedConn) Close() error {
	c.calls.Add(1)
	close(c.entered)
	<-c.release
	_ = c.Conn.Close()
	return c.err
}

func TestManagementNetworkRetainsLateSocketAndCloseFailure(t *testing.T) {
	managementForTest(t)
	ctx, finish, err := AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	a, b := net.Pipe()
	defer b.Close()
	failure := errors.New("physical close failed")
	raw := &managementBlockedConn{Conn: a, entered: make(chan struct{}), release: make(chan struct{}), err: failure}
	CancelManagementNetwork()
	if _, err := OwnNetworkConn(ctx, raw); err == nil {
		t.Fatal("late socket accepted")
	}
	finish()
	<-raw.entered
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(raw.release)
	if err := WaitManagementNetwork(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("lost failure: %v", err)
	}
	if err := ResumeManagementNetwork(); !errors.Is(err, failure) {
		t.Fatalf("resumed failed path: %v", err)
	}
	if len(managementRun().resources) != 1 || raw.calls.Load() != 1 {
		t.Fatal("lost handle or repeated close")
	}
}

type blockedNetworkResolver struct {
	resolver.Resolver
	entered, release chan struct{}
}

func (*blockedNetworkResolver) Invalid() bool { return true }
func (r *blockedNetworkResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	close(r.entered)
	<-r.release
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestManagementNetworkWaitIncludesDialAddressResolution(t *testing.T) {
	managementForTest(t)
	r := &blockedNetworkResolver{entered: make(chan struct{}), release: make(chan struct{})}
	var calls atomic.Int32
	d := dialer.NetDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	})
	result := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(context.Background(), "tcp4", "resolution-epoch.test:80", dialer.WithResolver(r), dialer.WithNetDialer(d))
		result <- err
	}()
	<-r.entered
	CancelManagementNetwork()
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forgot resolution: %v", err)
	}
	close(r.release)
	if err := <-result; err == nil {
		t.Fatal("canceled resolution led to success")
	}
	if err := WaitManagementNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("late resolution opened a new socket")
	}
}
