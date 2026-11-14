package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/sys/unix"
)

// This handler cannot initiate physical traffic. The probe only constructs and
// closes the upstream stack; it is not a forwarding or protocol acceptance test.
type rejectHandler struct{}

func (*rejectHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, tun.ErrDrop
}
func (*rejectHandler) NewError(context.Context, error) {}
func (*rejectHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	return c.Close()
}
func (*rejectHandler) NewPacket(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
	b.Release()
}

func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return "success"
}
func fdObservation(fd int) map[string]any {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return map[string]any{"fd": fd, "fstat": errorText(err), "mode": st.Mode, "fcntl": errorText(flagErr), "fdFlags": flags}
}

//export cb_probe_tun
func cb_probe_tun(original C.int) *C.char {
	data, _ := json.Marshal(probeIPCapabilities(int(original)))
	return C.CString(string(data))
}

func legacyTunProbe(original C.int) *C.char {
	result := map[string]any{"originalBefore": fdObservation(int(original)), "pid": unix.Getpid()}
	duplicate, err := unix.FcntlInt(uintptr(original), unix.F_DUPFD_CLOEXEC, 3)
	result["duplicateResult"] = errorText(err)
	if err == nil {
		result["duplicateBefore"] = fdObservation(duplicate)
		options := tun.Options{FileDescriptor: duplicate, MTU: 1500, DNSMode: tun.DNSModeDisabled,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.85.1/24")}}
		device, newErr := tun.New(options)
		result["nativeTunNew"] = errorText(newErr)
		if newErr != nil {
			result["duplicateClose"] = errorText(unix.Close(duplicate))
		} else {
			ctx, cancel := context.WithCancel(context.Background())
			stack, stackErr := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: device, TunOptions: options, Handler: &rejectHandler{}, Logger: log.SingLogger})
			result["newStack"] = errorText(stackErr)
			if stackErr == nil {
				result["stackStart"] = errorText(stack.Start())
				cancel()
				result["stackClose"] = errorText(stack.Close())
			} else {
				cancel()
			}
			result["nativeTunClose"] = errorText(device.Close())
		}
		result["duplicateAfterClose"] = fdObservation(duplicate)
	}
	result["originalAfter"] = fdObservation(int(original))
	if failure, ok := result["stackStart"].(string); ok && strings.Contains(failure, "Fstat") {
		result["packetAdapter"] = probePacketAdapter(int(original))
	}
	result["ownership"] = "platform owns original; probe duplicates once; native Tun owns duplicate after successful New"
	data, _ := json.Marshal(result)
	return C.CString(string(data))
}
