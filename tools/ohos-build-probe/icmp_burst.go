package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

// Three sequences on one kernel-assigned identifier exercise upstream reuse.
func kernelPingBurst() []any {
	results := []any{}
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if e != nil {
		return []any{map[string]any{"socket": errorText(e)}}
	}
	defer unix.Close(fd)
	if e = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, probeTunName); e != nil {
		return []any{map[string]any{"bind": errorText(e)}}
	}
	if e = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}); e != nil {
		return []any{map[string]any{"timeout": errorText(e)}}
	}
	for i := 1; i <= 3; i++ {
		nonce := fmt.Sprintf("is88/%d/%d/burst-%d", os.Getpid(), time.Now().UnixNano(), i)
		r := map[string]any{"name": "burst", "nonce": nonce, "seq": 100 + i}
		wire, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 88, Seq: 100 + i, Data: []byte(nonce)}}).Marshal(nil)
		evidence("client-send", r)
		e = unix.Sendto(fd, wire, 0, &unix.SockaddrInet4{Addr: [4]byte{192, 168, 3, 2}})
		r["send"] = errorText(e)
		addr, ae := unix.Getsockname(fd)
		r["getsockname"] = errorText(ae)
		if a, ok := addr.(*unix.SockaddrInet4); ok {
			r["kernelIdentifier"] = a.Port
		}
		if e == nil {
			b := make([]byte, 2048)
			n, _, re := unix.Recvfrom(fd, b, 0)
			r["read"] = errorText(re)
			if re == nil {
				r["replyHex"] = hex.EncodeToString(b[:n])
				m, pe := icmp.ParseMessage(1, b[:n])
				r["parse"] = errorText(pe)
				if pe == nil {
					if echo, ok := m.Body.(*icmp.Echo); ok {
						r["nonceMatches"] = string(echo.Data) == nonce
						r["sequenceMatches"] = echo.Seq == 100+i
						r["replyIdentifier"] = echo.ID
					}
				}
			}
		}
		evidence("client-result", r)
		results = append(results, r)
	}
	return results
}
