package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	st "github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/hysteria/conns/faketcp"
	tun "github.com/metacubex/sing-tun"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

var probeHome string
var probeTunName string
var evidenceMu sync.Mutex
var protectMu sync.Mutex
var protectSequence int

func evidence(kind string, data any) {
	evidenceMu.Lock()
	defer evidenceMu.Unlock()
	b, _ := json.Marshal(map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "pid": os.Getpid(), "kind": kind, "data": data})
	f, e := os.OpenFile(filepath.Join(probeHome, "ip-events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
}

// A bounded, probe-only handshake with the extension's real VpnConnection.protect.
// The originating syscall.RawConn.Control stays active until the acknowledgement.
// No product bridge or upstream source is changed.
func protectSocket(network, address string, conn syscall.RawConn) error {
	protectMu.Lock()
	defer protectMu.Unlock()
	protectSequence++
	seq := protectSequence
	var result error
	err := conn.Control(func(fd uintptr) {
		typ, te := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		req := map[string]any{"seq": seq, "fd": int(fd), "network": network, "address": address, "socketType": typ, "socketTypeError": errorText(te)}
		evidence("protect-request", req)
		b, _ := json.Marshal(req)
		path := filepath.Join(probeHome, "protect-request.json")
		if e := os.WriteFile(path+".tmp", b, 0600); e != nil {
			result = e
			return
		}
		if e := os.Rename(path+".tmp", path); e != nil {
			result = e
			return
		}
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			b, e := os.ReadFile(filepath.Join(probeHome, "protect-ack.json"))
			var ack struct {
				Seq   int    `json:"seq"`
				Error string `json:"error"`
			}
			if e == nil && json.Unmarshal(b, &ack) == nil && ack.Seq == seq {
				evidence("protect-ack", ack)
				if ack.Error != "" {
					result = fmt.Errorf("platform protect: %s", ack.Error)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		result = fmt.Errorf("protect acknowledgement timeout seq=%d", seq)
	})
	if err != nil {
		return err
	}
	return result
}

type observedICMP struct {
	rejectHandler
	upstream *st.ListenerHandler
}

func (h *observedICMP) PrepareConnection(network string, source, dest M.Socksaddr, rc tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	evidence("prepare-enter", map[string]any{"network": network, "source": source.String(), "target": dest.String(), "fakeIP": resolver.IsFakeIP(dest.Addr)})
	d, e := h.upstream.PrepareConnection(network, source, dest, rc, timeout)
	evidence("prepare-result", map[string]any{"target": dest.String(), "error": errorText(e), "nilDestination": d == nil})
	return d, e
}
func (*observedICMP) NewError(_ context.Context, e error) { evidence("handler-error", errorText(e)) }

func socketCapability(family, typ, protocol int) map[string]any {
	fd, e := unix.Socket(family, typ|unix.SOCK_CLOEXEC, protocol)
	r := map[string]any{"family": family, "type": typ, "protocol": protocol, "socket": errorText(e)}
	if e == nil {
		r["close"] = errorText(unix.Close(fd))
	}
	evidence("socket-capability", r)
	return r
}
func fakeTCPCapability() map[string]any {
	r := map[string]any{"target": "192.168.3.2:18787", "scope": "raw socket prerequisite; no firewall command, no remote service assumed"}
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	r["rawSocket"] = errorText(e)
	if e == nil {
		r["close"] = errorText(unix.Close(fd))
		r["dial"] = "not attempted: raw socket permitted; controlled peer and protection adaptation required"
	} else if e == unix.EPERM || e == unix.EACCES {
		// With this admission failure the fixed Dial returns before TCP or iptables.
		c, err := faketcp.Dial("tcp4", "192.168.3.2:18787")
		r["fixedUpstreamDial"] = errorText(err)
		if c != nil {
			r["unexpectedClose"] = errorText(c.Close())
		}
	} else {
		r["dial"] = "not attempted: unexpected raw socket error"
	}
	evidence("fake-tcp", r)
	return r
}

func kernelPing(name, target string, seq int) map[string]any {
	ip := netip.MustParseAddr(target)
	af, proto := unix.AF_INET, unix.IPPROTO_ICMP
	var kind icmp.Type = ipv4.ICMPTypeEcho
	var dst unix.Sockaddr
	if ip.Is6() {
		af = unix.AF_INET6
		proto = unix.IPPROTO_ICMPV6
		kind = ipv6.ICMPTypeEchoRequest
		dst = &unix.SockaddrInet6{Addr: ip.As16()}
	} else {
		dst = &unix.SockaddrInet4{Addr: ip.As4()}
	}
	nonce := fmt.Sprintf("ip87/%d/%d/%s", os.Getpid(), time.Now().UnixNano(), name)
	r := map[string]any{"name": name, "target": target, "nonce": nonce}
	fd, e := unix.Socket(af, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	r["socket"] = errorText(e)
	if e != nil {
		return r
	}
	defer unix.Close(fd)
	if probeTunName == "" {
		r["bindDevice"] = "TUN name unavailable; not sent"
		return r
	}
	e = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, probeTunName)
	r["bindDevice"] = errorText(e)
	r["device"] = probeTunName
	if e != nil {
		evidence("client-bind-failed", r)
		return r
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3})
	wire, e := (&icmp.Message{Type: kind, Code: 0, Body: &icmp.Echo{ID: 87, Seq: seq, Data: []byte(nonce)}}).Marshal(nil)
	if e != nil {
		r["marshal"] = e.Error()
		return r
	}
	evidence("client-send", r)
	e = unix.Sendto(fd, wire, 0, dst)
	r["send"] = errorText(e)
	if e != nil {
		return r
	}
	b := make([]byte, 2048)
	n, from, e := unix.Recvfrom(fd, b, 0)
	r["read"] = errorText(e)
	r["bytes"] = n
	r["from"] = fmt.Sprint(from)
	if e == nil {
		r["replyHex"] = hex.EncodeToString(b[:n])
		msg, pe := icmp.ParseMessage(proto, b[:n])
		r["parse"] = errorText(pe)
		if pe == nil {
			r["replyType"] = fmt.Sprint(msg.Type)
			if echo, ok := msg.Body.(*icmp.Echo); ok {
				r["nonceMatches"] = string(echo.Data) == nonce
				r["sequenceMatches"] = echo.Seq == seq
			}
		}
	}
	evidence("client-result", r)
	return r
}

func probeIPCapabilities(original int) map[string]any {
	r := map[string]any{"pid": os.Getpid(), "uid": os.Getuid(), "original": fdObservation(original)}
	ifr, ifrErr := unix.NewIfreq("")
	if ifrErr == nil {
		ifrErr = unix.IoctlIfreq(original, unix.TUNGETIFF, ifr)
	}
	r["tunNameIoctl"] = errorText(ifrErr)
	if ifrErr == nil {
		probeTunName = ifr.Name()
	}
	r["tunName"] = probeTunName
	evidence("start", r)
	caps := []any{}
	for _, af := range []int{unix.AF_INET, unix.AF_INET6} {
		p := unix.IPPROTO_ICMP
		if af == unix.AF_INET6 {
			p = unix.IPPROTO_ICMPV6
		}
		for _, t := range []int{unix.SOCK_RAW, unix.SOCK_DGRAM} {
			caps = append(caps, socketCapability(af, t, p))
		}
	}
	r["capabilities"] = caps
	r["fakeTCP"] = fakeTCPCapability()
	fd, e := unix.FcntlInt(uintptr(original), unix.F_DUPFD_CLOEXEC, 3)
	r["duplicate"] = errorText(e)
	if e != nil {
		return r
	}
	sys := DefaultDescriptorSystem()
	owner := consumeDescriptor(sys, fd)
	if e = sys.SetNonblock(fd); e != nil {
		owner.close()
		r["nonblock"] = e.Error()
		return r
	}
	rd, wr, e := sys.NewWake()
	ro, wo := consumeDescriptor(sys, rd), consumeDescriptor(sys, wr)
	if e != nil || !ro.valid || !wo.valid {
		owner.close()
		ro.close()
		wo.close()
		r["wake"] = "failed"
		return r
	}
	ctx, cancel := context.WithCancel(context.Background())
	dev := &packetAdapter{fd: fd, owner: owner, system: sys, wakeRead: ro, wakeWrite: wo, ep: channel.New(128, 1500, ""), ctx: ctx, cancel: cancel}
	opts := tun.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.87.1/24")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd87::1/64")}}
	p4, e := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.19.87.0/24"), Size: 64})
	if e != nil {
		r["fakePool"] = e.Error()
		dev.Close()
		return r
	}
	p6, e := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("fd88::/64"), Size: 64})
	if e != nil {
		r["fakePool6"] = e.Error()
		dev.Close()
		return r
	}
	resolver.DefaultHostMapper = dns.NewEnhancer(dns.EnhancerConfig{IPv6: true, EnhancedMode: C.DNSFakeIP, FakeIPPool: p4, FakeIPPool6: p6})
	dialer.DefaultSocketHook = protectSocket
	defer func() { dialer.DefaultSocketHook = nil; resolver.DefaultHostMapper = nil }()
	h := &observedICMP{upstream: &st.ListenerHandler{Inet4Address: opts.Inet4Address, Inet6Address: opts.Inet6Address}}
	server, e := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: dev, TunOptions: opts, Handler: h, Logger: log.SingLogger, ICMPTimeout: 2 * time.Second})
	r["newStack"] = errorText(e)
	if e == nil {
		e = server.Start()
		r["start"] = errorText(e)
		if e == nil {
			dev.start()
			results := []any{}
			for i, t := range [][2]string{{"ordinary4", "192.168.3.2"}, {"ordinary6", "240e:3bb:2e78:79f1:18aa:f3a:4683:2"}, {"fake4", "198.19.87.4"}, {"fake6", "fd88::4"}, {"tun-subnet4", "198.18.87.2"}, {"tun-subnet6", "fd87::2"}, {"tun-self4", "198.18.87.1"}, {"tun-self6", "fd87::1"}} {
				results = append(results, kernelPing(t[0], t[1], i+1))
			}
			r["pings"] = results
			// A shell client can bind to the observed interface even when this
			// ordinary app cannot query TUNGETIFF. Its echo is evidence only when
			// these packet/PrepareConnection/protect receipts show the core path.
			r["externalClientWindowSeconds"] = 60
			evidence("external-client-window", "60 seconds; explicit interface binding required")
			time.Sleep(60 * time.Second)
		}
		r["stackClose"] = errorText(server.Close())
	}
	r["adapterClose"] = errorText(dev.Close())
	r["rxPackets"] = dev.rx.Load()
	r["txPackets"] = dev.tx.Load()
	r["ioFailures"] = dev.failures.Load()
	r["tunClose"] = owner.receipt()
	r["wakeReadClose"] = ro.receipt()
	r["wakeWriteClose"] = wo.receipt()
	r["originalAfter"] = fdObservation(original)
	evidence("complete", r)
	return r
}
