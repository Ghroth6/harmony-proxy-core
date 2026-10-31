package bridge

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	O "github.com/metacubex/mihomo/mobile/observation"
	mobileRuntime "github.com/metacubex/mihomo/mobile/runtime"
	"unsafe"
)

var mobileRuntimeManager = mobileRuntime.NewManager(mobileRuntime.DefaultDescriptorSystem(), &mobileProtectionGate)

func initializeRuntimeOutput(output **C.uint8_t, size *C.uint32_t) bool {
	if output != nil {
		*output = nil
	}
	if size != nil {
		*size = 0
	}
	return output != nil && size != nil
}
func runtimeOutput(receipt mobileRuntime.Receipt, output **C.uint8_t, size *C.uint32_t) C.int32_t {
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) == 0 || len(encoded) > O.Current().ReplyBytes {
		return 2
	}
	buffer := C.CBytes(encoded)
	if buffer == nil {
		return 2
	}
	*output = (*C.uint8_t)(buffer)
	*size = C.uint32_t(len(encoded))
	return 0
}

//export cb_runtime_start_v1
func cb_runtime_start_v1(generation, transfer C.uint64_t, fd C.int32_t, input *C.uint8_t, inputSize C.uint32_t, request *C.uint8_t, requestSize C.uint32_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	var handoff *mobileRuntime.Transfer
	started := false
	defer func() {
		if recover() != nil {
			status = 2
			if handoff != nil && !started {
				handoff.Reject("ABI_FAILURE")
			}
		}
	}()
	// Consumption deliberately precedes all argument checks, including output
	// pointers. After this entry the caller must recover via the exact transfer.
	handoff = mobileRuntimeManager.Consume(uint64(generation), uint64(transfer), int(fd))
	if !initializeRuntimeOutput(output, size) {
		handoff.Reject("ABI_BOUNDS")
		return 1
	}
	if input == nil || request == nil || inputSize == 0 || inputSize > mobileRuntime.MaxInputBytes || requestSize == 0 || requestSize > mobileRuntime.MaxRequestBytes {
		handoff.Reject("ABI_BOUNDS")
		return 1
	}
	bytes := C.GoBytes(unsafe.Pointer(input), C.int(inputSize))
	envelope := C.GoBytes(unsafe.Pointer(request), C.int(requestSize))
	started = true
	return runtimeOutput(mobileRuntimeManager.Start(handoff, bytes, envelope), output, size)
}

//export cb_runtime_stop_v1
func cb_runtime_stop_v1(generation C.uint64_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	return runtimeOutput(mobileRuntimeManager.Stop(uint64(generation)), output, size)
}

//export cb_runtime_query_v1
func cb_runtime_query_v1(generation, transfer C.uint64_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	return runtimeOutput(mobileRuntimeManager.Query(uint64(generation), uint64(transfer)), output, size)
}
