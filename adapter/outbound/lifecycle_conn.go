package outbound

import (
	"context"
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

// The wrapper (not the raw connection stored in the lifetime) keeps the adapter
// alive. I/O retains it through the call just as the existing AddRef wrappers do.
type leasedConn struct {
	C.Conn
	lease *adapterLease
	owner *autoCloseProxyAdapter
}

func (c *leasedConn) Close() error {
	defer runtime.KeepAlive(c.owner)
	return c.lease.close()
}

func (c *leasedConn) Read(b []byte) (int, error) {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.Read(b)
}

func (c *leasedConn) Write(b []byte) (int, error) {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.Write(b)
}

func (c *leasedConn) ReadBuffer(b *buf.Buffer) error {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.ReadBuffer(b)
}

func (c *leasedConn) WriteBuffer(b *buf.Buffer) error {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.WriteBuffer(b)
}

func (c *leasedConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.LocalAddr()
}

func (c *leasedConn) RemoteAddr() net.Addr {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.RemoteAddr()
}

func (c *leasedConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.SetDeadline(t)
}

func (c *leasedConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.SetReadDeadline(t)
}

func (c *leasedConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.Conn.SetWriteDeadline(t)
}

// Preserve discovery of handshake, read waiter and protocol capabilities.
// Copy helpers may bypass this wrapper for I/O, but full Close belongs here.
func (c *leasedConn) Upstream() any           { return c.Conn }
func (c *leasedConn) ReaderReplaceable() bool { return true }
func (c *leasedConn) WriterReplaceable() bool { return true }

type leasedReadConn struct {
	*leasedConn
	readCloser SN.ReadCloser
}

func (c *leasedReadConn) CloseRead() error {
	defer runtime.KeepAlive(c.owner)
	return c.readCloser.CloseRead()
}

type leasedWriteConn struct {
	*leasedConn
	writeCloser SN.WriteCloser
}

func (c *leasedWriteConn) CloseWrite() error {
	defer runtime.KeepAlive(c.owner)
	return c.writeCloser.CloseWrite()
}

type leasedDuplexConn struct {
	*leasedReadConn
	writeCloser SN.WriteCloser
}

func (c *leasedDuplexConn) CloseWrite() error {
	defer runtime.KeepAlive(c.owner)
	return c.writeCloser.CloseWrite()
}

func newLeasedConn(raw C.Conn, lease *adapterLease, owner *autoCloseProxyAdapter) C.Conn {
	c := &leasedConn{Conn: raw, lease: lease, owner: owner}
	readCloser, canReadClose := N.FindUpstream[SN.ReadCloser](raw, nil)
	writeCloser, canWriteClose := N.FindUpstream[SN.WriteCloser](raw, nil)
	switch {
	case canReadClose && canWriteClose:
		return &leasedDuplexConn{leasedReadConn: &leasedReadConn{c, readCloser}, writeCloser: writeCloser}
	case canReadClose:
		return &leasedReadConn{c, readCloser}
	case canWriteClose:
		return &leasedWriteConn{c, writeCloser}
	default:
		return c
	}
}

type leasedPacketConn struct {
	C.PacketConn
	lease *adapterLease
	owner *autoCloseProxyAdapter
}

func (c *leasedPacketConn) Close() error {
	defer runtime.KeepAlive(c.owner)
	return c.lease.close()
}

func (c *leasedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.ReadFrom(b)
}

func (c *leasedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.WriteTo(b, addr)
}

func (c *leasedPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.WaitReadFrom()
}

func (c *leasedPacketConn) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.ResolveUDP(ctx, metadata)
}

func (c *leasedPacketConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.LocalAddr()
}

func (c *leasedPacketConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.SetDeadline(t)
}

func (c *leasedPacketConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.SetReadDeadline(t)
}

func (c *leasedPacketConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.owner)
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *leasedPacketConn) Upstream() any           { return c.PacketConn }
func (c *leasedPacketConn) ReaderReplaceable() bool { return true }
func (c *leasedPacketConn) WriterReplaceable() bool { return true }

type leasedSingPacketConn struct {
	*leasedPacketConn
	packetConn SN.NetPacketConn
}

func (c *leasedSingPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	defer runtime.KeepAlive(c.owner)
	return c.packetConn.ReadPacket(b)
}

func (c *leasedSingPacketConn) WritePacket(b *buf.Buffer, addr M.Socksaddr) error {
	defer runtime.KeepAlive(c.owner)
	return c.packetConn.WritePacket(b, addr)
}

func newLeasedPacketConn(raw C.PacketConn, lease *adapterLease, owner *autoCloseProxyAdapter) C.PacketConn {
	c := &leasedPacketConn{PacketConn: raw, lease: lease, owner: owner}
	if singConn, ok := raw.(SN.NetPacketConn); ok {
		return &leasedSingPacketConn{c, singConn}
	}
	return c
}
