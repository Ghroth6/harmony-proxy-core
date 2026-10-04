package session_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/transport/anytls"
	"github.com/metacubex/mihomo/transport/vmess"
	M "github.com/metacubex/sing/common/metadata"
)

type failedTLSCloseConn struct {
	net.Conn
	closeErr error
	closes   atomic.Int32
}

func (c *failedTLSCloseConn) Close() error {
	c.closes.Add(1)
	return errors.Join(c.Conn.Close(), c.closeErr)
}

type failedTLSDialer struct{ conn net.Conn }

func (d failedTLSDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d failedTLSDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP dial")
}

// Exercise the real TLS construction path: a failed handshake must hand its
// physical connection back to the pool for tracked cleanup, including errors.
func TestAnyTLSHandshakeFailureRetainsPhysicalCloseError(t *testing.T) {
	left, right := net.Pipe()
	_ = right.Close()
	want := errors.New("TLS underlying close failed")
	physical := &failedTLSCloseConn{Conn: left, closeErr: want}
	c := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password:  "test",
		Server:    M.ParseSocksaddr("127.0.0.1:443"),
		Dialer:    failedTLSDialer{conn: physical},
		TLSConfig: &vmess.TLSConfig{Host: "example.invalid", SkipCertVerify: true},
	})
	if _, err := c.CreateProxy(context.Background(), M.ParseSocksaddr("example.invalid:443")); !errors.Is(err, want) {
		t.Fatalf("CreateProxy lost physical cleanup failure: %v", err)
	}
	if err := c.Close(); !errors.Is(err, want) {
		t.Fatalf("Client.Close forgot handshake cleanup failure: %v", err)
	}
	if physical.closes.Load() != 1 {
		t.Fatalf("physical Close count = %d", physical.closes.Load())
	}
}
