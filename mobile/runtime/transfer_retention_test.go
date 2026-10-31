package runtime_test

import (
	R "github.com/metacubex/mihomo/mobile/runtime"
	"testing"
)

func TestDescriptorBookHasNoCountBasedOwnershipFault(t *testing.T) {
	system := newDescriptors()
	manager := R.NewManager(system)
	transfers := make([]*R.Transfer, 0, 96)
	for i := 1; i <= 96; i++ {
		fd := 100 + i
		system.open[fd] = true
		transfers = append(transfers, manager.Consume(uint64(i), uint64(i), fd))
		if got := manager.Query(uint64(i), uint64(i)); got.OwnershipFault || !got.TransferConsumed {
			t.Fatalf("valid descriptor rejected by inventory size: %+v", got)
		}
	}
	for i, transfer := range transfers {
		// Invalid request still exercises the real ownership/close path.
		receipt := manager.Start(transfer, nil, []byte("{}"))
		if receipt.OwnershipFault || receipt.Cleanup != "complete" || system.closes[101+i] != 1 {
			t.Fatalf("descriptor %d was lost: %+v", i, receipt)
		}
	}
}
