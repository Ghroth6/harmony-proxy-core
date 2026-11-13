package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/sys/unix"
)

// Only packet I/O changes. The server, TCP/UDP forwarders and protocol semantics
// are the pinned upstream NewStack("gvisor"). No copy of the product runtime.
type packetAdapter struct {
	fd                         int
	owner, wakeRead, wakeWrite *descriptorOwner
	system                     DescriptorSystem
	ep                         *channel.Endpoint
	ctx                        context.Context
	cancel                     context.CancelFunc
	workers                    sync.WaitGroup
	writes                     sync.Mutex
	rx                         atomic.Int64
	tx                         atomic.Int64
	failures                   atomic.Int64
	closed                     sync.Once
	closeError                 error
}

func (d *packetAdapter) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return d.ep, stack.NICOptions{}, nil
}
func (d *packetAdapter) Read(p []byte) (int, error) { return d.system.Read(d.fd, p) }
func (d *packetAdapter) Write(p []byte) (int, error) {
	d.writes.Lock()
	defer d.writes.Unlock()
	for d.ctx.Err() == nil {
		n, err := d.system.Write(d.fd, p)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			if err = d.system.Poll(d.ctx, d.fd, d.wakeRead.fd, true); err == nil {
				continue
			}
		}
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err == nil {
			d.tx.Add(1)
		} else {
			d.failures.Add(1)
		}
		return n, err
	}
	return 0, d.ctx.Err()
}
func (d *packetAdapter) WritePacket(p *stack.PacketBuffer) (int, error) {
	var bytes []byte
	for _, part := range p.AsSlices() {
		bytes = append(bytes, part...)
	}
	return d.Write(bytes)
}
func (d *packetAdapter) start() {
	d.workers.Add(2)
	go func() {
		defer d.workers.Done()
		data := make([]byte, 1501)
		for d.ctx.Err() == nil {
			n, err := d.system.Read(d.fd, data)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				if err = d.system.Poll(d.ctx, d.fd, d.wakeRead.fd, false); err == nil {
					continue
				}
				if d.ctx.Err() == nil {
					d.failures.Add(1)
				}
				return
			}
			if err != nil || n <= 0 || n > 1500 {
				d.failures.Add(1)
				return
			}
			var protocol tcpip.NetworkProtocolNumber
			switch data[0] >> 4 {
			case 4:
				protocol = header.IPv4ProtocolNumber
			case 6:
				protocol = header.IPv6ProtocolNumber
			default:
				d.failures.Add(1)
				continue
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data[:n]...))})
			d.rx.Add(1)
			d.ep.InjectInbound(protocol, packet)
			packet.DecRef()
		}
	}()
	go func() {
		defer d.workers.Done()
		for {
			packet := d.ep.ReadContext(d.ctx)
			if packet == nil {
				return
			}
			_, _ = d.WritePacket(packet)
			packet.DecRef()
		}
	}()
}
func (d *packetAdapter) Close() error {
	d.closed.Do(func() {
		d.cancel()
		_, err := d.system.Write(d.wakeWrite.fd, []byte{1})
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			d.closeError = err
		}
		d.ep.Close()
		d.workers.Wait()
		for _, owner := range []*descriptorOwner{d.owner, d.wakeRead, d.wakeWrite} {
			owner.close()
			if receipt := owner.receipt(); receipt.CloseResult != 0 {
				d.closeError = errors.New("descriptor close failed")
			}
		}
	})
	return d.closeError
}

var _ tun.GVisorTun = (*packetAdapter)(nil)

type localEcho struct {
	calls  sync.WaitGroup
	tcp    atomic.Int64
	udp    atomic.Int64
	errors atomic.Int64
}

func (*localEcho) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}
func (h *localEcho) NewError(context.Context, error) { h.errors.Add(1) }
func (h *localEcho) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	h.calls.Add(1)
	defer h.calls.Done()
	defer c.Close()
	h.tcp.Add(1)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	p := make([]byte, len("cf85-tcp-20261114"))
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	_, err := c.Write(p)
	return err
}
func (h *localEcho) NewPacket(_ context.Context, _ netip.AddrPort, p *buf.Buffer, m M.Metadata, initialize func(N.PacketConn) N.PacketWriter) {
	h.calls.Add(1)
	defer h.calls.Done()
	h.udp.Add(1)
	if err := initialize(nil).WritePacket(p, m.Destination); err != nil {
		h.errors.Add(1)
	}
}
func kernelEcho(network string) map[string]any {
	result := map[string]any{"network": network, "target": "198.18.85.2:18585"}
	c, err := net.DialTimeout(network, "198.18.85.2:18585", 2*time.Second)
	result["dial"] = errorText(err)
	if err != nil {
		return result
	}
	closed := false
	defer func() {
		if !closed {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("cf85-" + network + "-20261114")
	n, err := c.Write(payload)
	result["sent"] = n
	result["write"] = errorText(err)
	if err != nil {
		return result
	}
	reply := make([]byte, len(payload))
	n, err = io.ReadFull(c, reply)
	result["received"] = n
	result["read"] = errorText(err)
	result["echoMatches"] = string(reply) == string(payload)
	result["close"] = errorText(c.Close())
	closed = true
	return result
}
func probePacketAdapter(original int) map[string]any {
	result := map[string]any{"scope": "real VPN fd, upstream gVisor, local IPv4 TCP/UDP echo; no physical dial from handler"}
	fd, err := unix.FcntlInt(uintptr(original), unix.F_DUPFD_CLOEXEC, 3)
	result["duplicate"] = errorText(err)
	if err != nil {
		return result
	}
	system := DefaultDescriptorSystem()
	owner := consumeDescriptor(system, fd)
	if err = system.SetNonblock(fd); err != nil {
		owner.close()
		result["error"] = err.Error()
		result["tunClose"] = owner.receipt()
		return result
	}
	read, write, err := system.NewWake()
	wakeRead, wakeWrite := consumeDescriptor(system, read), consumeDescriptor(system, write)
	if err != nil || !wakeRead.valid || !wakeWrite.valid {
		owner.close()
		wakeRead.close()
		wakeWrite.close()
		result["error"] = "wake creation failed"
		return result
	}
	ctx, cancel := context.WithCancel(context.Background())
	device := &packetAdapter{fd: fd, owner: owner, system: system, wakeRead: wakeRead, wakeWrite: wakeWrite, ep: channel.New(128, 1500, ""), ctx: ctx, cancel: cancel}
	handler := &localEcho{}
	server, err := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: device, TunOptions: tun.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.85.1/24")}}, Handler: handler, Logger: log.SingLogger})
	result["newStack"] = errorText(err)
	if err == nil {
		err = server.Start()
		result["start"] = errorText(err)
		if err == nil {
			device.start()
			result["tcp"] = kernelEcho("tcp")
			result["udp"] = kernelEcho("udp")
		}
		result["stackClose"] = errorText(server.Close())
	}
	result["adapterClose"] = errorText(device.Close())
	result["tunClose"] = owner.receipt()
	result["wakeReadClose"] = wakeRead.receipt()
	result["wakeWriteClose"] = wakeWrite.receipt()
	done := make(chan struct{})
	go func() { handler.calls.Wait(); close(done) }()
	select {
	case <-done:
		result["handlersJoined"] = true
	case <-time.After(4 * time.Second):
		result["handlersJoined"] = false
	}
	result["rxPackets"] = device.rx.Load()
	result["txPackets"] = device.tx.Load()
	result["ioFailures"] = device.failures.Load()
	result["tcpHandled"] = handler.tcp.Load()
	result["udpHandled"] = handler.udp.Load()
	result["handlerErrors"] = handler.errors.Load()
	result["duplicateAfterClose"] = fdObservation(fd)
	result["originalAfter"] = fdObservation(original)
	return result
}
