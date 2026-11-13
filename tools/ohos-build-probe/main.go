// Host-build-only probe for Ghroth6/clashbox-meta#82. Not a product ABI.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/metacubex/mihomo/config"
	CPath "github.com/metacubex/mihomo/constant"
)

//export cb_probe_init
func cb_probe_init(home *C.char) {
	if home != nil {
		CPath.SetHomeDir(C.GoString(home))
	}
}

// cb_probe_parse returns an owned UTF-8 error string, or nil on success.
// This probe is compiled only; invoking the upstream parser may create resources.
//
//export cb_probe_parse
func cb_probe_parse(input *C.char) *C.char {
	if input == nil {
		return C.CString("nil configuration")
	}
	_, err := config.Parse([]byte(C.GoString(input)))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export cb_probe_free
func cb_probe_free(value *C.char) { C.free(unsafe.Pointer(value)) }

func main() {}
