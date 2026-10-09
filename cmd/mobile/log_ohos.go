//go:build ohos && cgo

package main

/*
#cgo LDFLAGS: -lhilog_ndk.z
#include <hilog/log.h>
#include <stdlib.h>
static void cb_mobile_log(int level, const char *message) {
    OH_LOG_Print(LOG_APP, (LogLevel)level, 0x0000, "clashoh", "CORE %{public}s", message);
}
*/
import "C"

import (
	"unsafe"

	"github.com/metacubex/mihomo/log"
)

type hiLogOutput struct{}

func (hiLogOutput) WriteMobileEvent(event log.MobileEvent) {
	level := C.int(C.LOG_INFO)
	if event.Class != log.ClassNone {
		level = C.int(C.LOG_WARN)
	}
	if event.Stage == log.StageRuntimeFailed || event.Stage == log.StageCleanupFailed {
		level = C.int(C.LOG_ERROR)
	}
	message := C.CString(event.String())
	if message == nil {
		return
	}
	defer C.free(unsafe.Pointer(message))
	C.cb_mobile_log(level, message)
}
func init() { log.InstallMobileOutput(hiLogOutput{}) }
