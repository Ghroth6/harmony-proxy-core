package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	WGConn "github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
)

// The peer is a test-only userspace device from the pinned dependency, not a
// new core inbound. No OS TUN or routes are needed for these encrypted exchanges.
type wireGuardTestBind struct {
	WGConn.Bind
	port uint16
}

func (b *wireGuardTestBind) Open(port uint16) ([]WGConn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	b.port = actual
	return fns, actual, err
}

type wireGuardTestPeer struct {
	stack wireguardDevice
	key   *ecdh.PrivateKey
	port  uint16
	ips   []netip.Addr
}

func wireGuardTestKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newWireGuardTestPeer(t *testing.T, client *ecdh.PrivateKey, suffix int) wireGuardTestPeer {
	t.Helper()
	key := wireGuardTestKey(t)
	ips := []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.66.0.%d", suffix)), netip.MustParseAddr(fmt.Sprintf("fd66::%d", suffix))}
	stack, err := newIPStack(IPStackOption{Mode: ipStackMips}, []netip.Prefix{
		netip.PrefixFrom(ips[0], 32), netip.PrefixFrom(ips[1], 128),
	}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := newWireguardDevice(stack)
	if err != nil {
		_ = stack.Close()
		t.Fatal(err)
	}
	bind := &wireGuardTestBind{Bind: WGConn.NewStdNetBind()}
	peer := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""), 1)
	t.Cleanup(peer.Close)
	if err := peer.IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\npublic_key=" +
		hex.EncodeToString(client.PublicKey().Bytes()) + "\nallowed_ip=10.66.0.2/32\nallowed_ip=fd66::2/128\n"); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	return wireGuardTestPeer{tun, key, bind.port, ips}
}

func TestWireGuardTunnelLifecycle(t *testing.T) {
	modes := []string{ipStackAuto}
	if features.WithGVisor {
		modes = append(modes, ipStackGVisor)
	}
	for _, mode := range modes {
		for _, peerCount := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d-peers", mode, peerCount), func(t *testing.T) {
				key := wireGuardTestKey(t)
				d := &poolTestDialer{sockets: make(chan *poolTestSocket, 8)}
				option := WireGuardOption{
					BasicOption: BasicOption{DialerForAPI: d},
					Name:        "wireguard-test", Ip: "10.66.0.2/32", Ipv6: "fd66::2/128",
					PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), Workers: 1,
					UDP: true, IPStack: IPStackOption{Mode: mode},
				}
				var peers []wireGuardTestPeer
				for i := 0; i < peerCount; i++ {
					p := newWireGuardTestPeer(t, key, 1+2*i)
					peers = append(peers, p)
					peerOption := WireGuardPeerOption{Server: "127.0.0.1", Port: int(p.port),
						PublicKey:  base64.StdEncoding.EncodeToString(p.key.PublicKey().Bytes()),
						AllowedIPs: []string{p.ips[0].String() + "/32", p.ips[1].String() + "/128"}}
					if peerCount == 1 {
						option.WireGuardPeerOption = peerOption
					} else {
						option.Peers = append(option.Peers, peerOption)
					}
				}
				client, err := NewWireGuard(option)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				for _, p := range peers {
					for _, ip := range p.ips {
						wireGuardTestExchange(t, client, p.stack, ip)
					}
				}
				pending, err := client.tunDevice.ListenUDP(context.Background(), "udp", netip.AddrPort{})
				if err != nil {
					t.Fatal(err)
				}
				defer pending.Close()
				readDone := make(chan error, 1)
				go func() { _, _, err := pending.ReadFrom(make([]byte, 64)); readDone <- err }()
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-client.device.(*device.Device).Wait():
				default:
					t.Fatal("official device Close returned before its workers joined")
				}
				poolTestClosed(t, d)
				select {
				case err := <-readDone:
					if err == nil {
						t.Fatal("closed stack returned a successful pending read")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("stack Close did not release pending UDP read")
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func wireGuardTestExchange(t *testing.T, client *WireGuard, peer wireguardDevice, ip netip.Addr) {
	t.Helper()
	dst := netip.AddrPortFrom(ip, 8080)
	l, err := peer.ListenTCP(context.Background(), "tcp", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close(); done <- struct{}{} }(); _, _ = io.Copy(c, c) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{DstIP: ip, DstPort: 8080}
	first, err := client.DialContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	poolTestEcho(t, first)
	cancel()
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer secondCancel()
	second, err := client.DialContext(secondCtx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = first.Close()
	poolTestEcho(t, second)
	_ = second.Close()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("peer TCP echo handler did not finish")
		}
	}
	udp, err := peer.ListenUDP(context.Background(), "udp", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpDone := make(chan error, 1)
	go func() {
		_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 128)
		n, addr, err := udp.ReadFrom(b)
		if err == nil {
			_, err = udp.WriteTo(b[:n], addr)
		}
		udpDone <- err
	}()
	c, err := client.ListenPacketContext(secondCtx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.WriteTo([]byte("wireguard-udp"), net.UDPAddrFromAddrPort(dst)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	n, addr, err := c.ReadFrom(b)
	if err != nil || string(b[:n]) != "wireguard-udp" || addr.String() != dst.String() {
		t.Fatalf("UDP echo n=%d addr=%v err=%v", n, addr, err)
	}
	if err := <-udpDone; err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardClosedStackStart(t *testing.T) {
	stack, err := newIPStack(IPStackOption{Mode: ipStackMips}, []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	tun, err := newWireguardDevice(stack)
	if !errors.Is(err, net.ErrClosed) || tun != nil {
		t.Fatalf("closed stack returned device=%v err=%v", tun, err)
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
}
