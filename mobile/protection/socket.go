package protection

import "errors"

// A probe has a single synchronous owner; Close follows ProtectSocket's return.
// Actual dialers pass their netFD RawConn, with the runtime's descriptor lock.
type probeSocket uintptr

func (s probeSocket) Control(fn func(uintptr)) error { fn(uintptr(s)); return nil }
func (probeSocket) Read(func(uintptr) bool) error    { return errors.New("probe cannot read") }
func (probeSocket) Write(func(uintptr) bool) error   { return errors.New("probe cannot write") }
