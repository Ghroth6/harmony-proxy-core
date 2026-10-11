package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/metacubex/mihomo/mobile/network"
)

var mobileNetworkController = network.NewController(mobileRuntimeManager.NetworkBusy)

//export cb_network_contract_version_v1
func cb_network_contract_version_v1() C.int32_t { return network.ContractVersion }

//export cb_network_submit_v1
func cb_network_submit_v1(input *C.uint8_t, inputSize C.uint32_t, operation *C.uint8_t, operationSize C.uint32_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	if input == nil || operation == nil || inputSize == 0 || inputSize > network.MaxInputBytes || operationSize == 0 || operationSize > 128 {
		return 1
	}
	bytes := C.GoBytes(unsafe.Pointer(input), C.int(inputSize))
	id := string(C.GoBytes(unsafe.Pointer(operation), C.int(operationSize)))
	encoded, err := json.Marshal(mobileNetworkController.Submit(id, bytes))
	if err != nil || len(encoded) == 0 || len(encoded) > network.MaxOutputBytes {
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
