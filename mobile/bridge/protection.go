package bridge

/*
#include "../include/cb_protection.h"
static inline int32_t cb_call_protect_v1(cb_protect_socket_fn_v1 callback,
    void *context, uint64_t generation, uint64_t request_id, int32_t fd) {
    return callback(context, generation, request_id, fd);
}
*/
import "C"

import (
	"unsafe"

	"github.com/metacubex/mihomo/mobile/protection"
)

var mobileProtectionGate protection.Gate
var mobileProtectionHookStatus = mobileProtectionGate.InstallDialerHook()

//export cb_protection_register_v1
func cb_protection_register_v1(generation C.uint64_t, callback C.cb_protect_socket_fn_v1, callbackContext unsafe.Pointer) C.int32_t {
	if callback == nil {
		return C.int32_t(protection.Invalid)
	}
	if mobileProtectionHookStatus != protection.Success {
		return C.int32_t(protection.Failed)
	}
	return C.int32_t(mobileProtectionGate.Register(uint64(generation), func(generation, request uint64, fd uintptr) int32 {
		if fd > 0x7fffffff {
			return protection.Failed
		}
		return int32(C.cb_call_protect_v1(callback, callbackContext, C.uint64_t(generation), C.uint64_t(request), C.int32_t(fd)))
	}))
}

//export cb_protection_unregister_v1
func cb_protection_unregister_v1(generation C.uint64_t) C.int32_t {
	return C.int32_t(mobileProtectionGate.Unregister(uint64(generation)))
}

//export cb_protection_probe_v1
func cb_protection_probe_v1(generation, request C.uint64_t) C.int32_t {
	return C.int32_t(mobileProtectionGate.Probe(uint64(generation), uint64(request)))
}

//export cb_protection_probe_observation_v1
func cb_protection_probe_observation_v1(generation, request C.uint64_t, identity *C.int64_t, before, after, closeResult *C.int32_t) C.int32_t {
	if identity == nil || before == nil || after == nil || closeResult == nil {
		return C.int32_t(protection.Invalid)
	}
	*identity, *before, *after, *closeResult = -1, -1, -1, -1
	if generation == 0 || generation > 0x7fffffff || request == 0 || request > 0x7fffffffffffffff {
		return C.int32_t(protection.Invalid)
	}
	receipt, ok := mobileProtectionGate.ProbeObservation(uint64(generation), uint64(request))
	if !ok {
		return C.int32_t(protection.Inactive)
	}
	*identity = C.int64_t(receipt.SocketIdentity)
	*before, *after, *closeResult = C.int32_t(receipt.BeforeSocket), C.int32_t(receipt.AfterSameSocket), C.int32_t(receipt.CloseResult)
	return C.int32_t(protection.Success)
}
