package main

/*
#include <stdint.h>
*/
import "C"

import mobileRuntime "github.com/metacubex/mihomo/mobile/runtime"

//export cb_runtime_contract_version_v1
func cb_runtime_contract_version_v1() C.int32_t { return mobileRuntime.ContractVersion }
