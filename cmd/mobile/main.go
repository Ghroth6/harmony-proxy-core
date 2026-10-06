// The mobile library exports byte buffers only; no Go or engine pointer escapes.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/metacubex/mihomo/mobile/validation"
)

//export cb_abi_version_v1
func cb_abi_version_v1() C.int32_t { return validation.ABIVersion }

//export cb_validate_v1
func cb_validate_v1(input *C.uint8_t, inputSize C.uint32_t, operation *C.uint8_t, operationSize C.uint32_t, output **C.uint8_t, outputSize *C.uint32_t) (status C.int32_t) {
	status = 1
	if output == nil || outputSize == nil {
		return
	}
	*output = nil
	*outputSize = 0
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	if (input == nil && inputSize != 0) || operation == nil || inputSize > validation.MaxInputBytes || operationSize == 0 || operationSize > validation.MaxOperationBytes {
		return
	}
	// Copy caller memory before entering validation. Nothing retains these C
	// pointers after this synchronous library call returns.
	bytes := C.GoBytes(unsafe.Pointer(input), C.int(inputSize))
	id := string(C.GoBytes(unsafe.Pointer(operation), C.int(operationSize)))
	receipt := validation.Validate(id, bytes)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return
	}
	buffer := C.CBytes(encoded)
	if buffer == nil {
		return
	}
	*output = (*C.uint8_t)(buffer)
	*outputSize = C.uint32_t(len(encoded))
	return 0
}

//export cb_free_v1
func cb_free_v1(output unsafe.Pointer) { C.free(output) }

func main() {}
