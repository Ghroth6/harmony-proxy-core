package bridge

/*
#include "../include/cb_log.h"
static inline void cb_deliver_log_v1(cb_log_fn_v1 callback, void *context,
    int32_t level, const uint8_t *message, uint64_t length) {
    callback(context, level, message, length);
}
*/
import "C"

import (
	"runtime"
	"unsafe"

	"github.com/metacubex/mihomo/mobile/logging"
)

//export cb_log_install_v1
func cb_log_install_v1(callback C.cb_log_fn_v1, context unsafe.Pointer) C.int32_t {
	if callback == nil {
		return -1
	}
	if !logging.Install(func(level int, message string) {
		C.cb_deliver_log_v1(callback, context, C.int32_t(level), (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(message))), C.uint64_t(len(message)))
		runtime.KeepAlive(message)
	}) {
		return -1
	}
	return 0
}
