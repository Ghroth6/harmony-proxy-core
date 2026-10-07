//go:build !with_gvisor

package runtime

type runEngine struct{}

func (*runEngine) fillReceipt(*Receipt)        {}
func (t *Transfer) start(StartRequest, []byte) { t.Reject("GVISOR_REQUIRED") }
func (t *Transfer) stop()                      { t.Reject("GVISOR_REQUIRED") }
