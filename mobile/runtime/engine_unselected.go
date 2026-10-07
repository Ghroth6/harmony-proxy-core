//go:build !with_gvisor

package runtime

type runEngine struct{}

const EngineAvailable = false

func (*runEngine) fillReceipt(*Receipt)        {}
func (t *Transfer) start(StartRequest, []byte) { t.Reject("GVISOR_REQUIRED") }
func (t *Transfer) stop() {
	t.mu.Lock()
	t.cancel()
	t.receipt.Phase = "stopping"
	t.receipt.Outcome = "pending"
	t.mu.Unlock()
}
