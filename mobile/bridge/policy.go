package bridge

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	constant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

var mobilePolicyOwner struct {
	sync.Mutex
	root   string
	engine *policy.Engine
}

//export cb_policy_contract_version_v1
func cb_policy_contract_version_v1() C.int32_t { return contract.ABIVersion }

//export cb_policy_storage_root_v1
func cb_policy_storage_root_v1(root *C.uint8_t, rootSize C.uint32_t) (status C.int32_t) {
	status = 2
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	if root == nil || rootSize == 0 || rootSize > 4096 {
		return 1
	}
	value := string(C.GoBytes(unsafe.Pointer(root), C.int(rootSize)))
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) {
		return 1
	}
	value = filepath.Clean(value)
	mobilePolicyOwner.Lock()
	defer mobilePolicyOwner.Unlock()
	if mobilePolicyOwner.engine != nil {
		if mobilePolicyOwner.root == value {
			return 0
		}
		return 1
	}
	owner, err := policy.NewEngine(value)
	if err != nil {
		return 1
	}
	if err := mobileRuntimeManager.BindPolicy(owner); err != nil {
		owner.Close()
		return 1
	}
	mobilePolicyOwner.root = value
	mobilePolicyOwner.engine = owner
	// The application supplies this private root once per process, before any
	// provider/cache activation. Preserve upstream relative path semantics.
	constant.SetHomeDir(value)
	return 0
}

func currentPolicyOwner() *policy.Engine {
	mobilePolicyOwner.Lock()
	defer mobilePolicyOwner.Unlock()
	return mobilePolicyOwner.engine
}
func policyOutput(value any, output **C.uint8_t, size *C.uint32_t) C.int32_t {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > contract.MaxResultBytes {
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

func policyValueInput(raw *C.uint8_t, rawSize C.uint32_t, control *C.uint8_t, controlSize C.uint32_t, operation *C.uint8_t, operationSize C.uint32_t) ([]byte, []byte, string, bool) {
	if raw == nil && rawSize != 0 || rawSize > contract.MaxControlBytes || control == nil || controlSize == 0 || controlSize > contract.MaxControlBytes || operation == nil || operationSize == 0 || operationSize > 128 {
		return nil, nil, "", false
	}
	return C.GoBytes(unsafe.Pointer(raw), C.int(rawSize)), C.GoBytes(unsafe.Pointer(control), C.int(controlSize)), string(C.GoBytes(unsafe.Pointer(operation), C.int(operationSize))), true
}

//export cb_policy_plan_v1
func cb_policy_plan_v1(raw *C.uint8_t, rawSize C.uint32_t, available *C.uint8_t, availableSize C.uint32_t, operation *C.uint8_t, operationSize C.uint32_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	bytes, control, id, valid := policyValueInput(raw, rawSize, available, availableSize, operation, operationSize)
	if !valid {
		return 1
	}
	owner := currentPolicyOwner()
	if owner == nil {
		return 1
	}
	receipt, err := owner.PlanJSON(id, bytes, control)
	if err != nil {
		return 1
	}
	return policyOutput(receipt, output, size)
}

//export cb_policy_validate_v1
func cb_policy_validate_v1(raw *C.uint8_t, rawSize C.uint32_t, contextJSON *C.uint8_t, contextSize C.uint32_t, operation *C.uint8_t, operationSize C.uint32_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	bytes, control, id, valid := policyValueInput(raw, rawSize, contextJSON, contextSize, operation, operationSize)
	if !valid {
		return 1
	}
	owner := currentPolicyOwner()
	if owner == nil {
		return 1
	}
	receipt, err := owner.ValidateJSON(id, bytes, control)
	if err != nil {
		return 1
	}
	return policyOutput(receipt, output, size)
}

//export cb_policy_resources_v1
func cb_policy_resources_v1(generation C.uint64_t, operation *C.uint8_t, operationSize C.uint32_t, output **C.uint8_t, size *C.uint32_t) (status C.int32_t) {
	status = 2
	if !initializeRuntimeOutput(output, size) {
		return 1
	}
	defer func() {
		if recover() != nil {
			status = 2
		}
	}()
	if operation == nil || operationSize == 0 || operationSize > 128 || generation == 0 || generation > 2147483647 {
		return 1
	}
	owner := currentPolicyOwner()
	if owner == nil {
		return 1
	}
	id := string(C.GoBytes(unsafe.Pointer(operation), C.int(operationSize)))
	return policyOutput(owner.QueryResources(id, uint64(generation)), output, size)
}
