package runtime_test

import (
	"strconv"
	"testing"

	R "github.com/metacubex/mihomo/mobile/runtime"
)

func TestKnownAbsentDescriptorDoesNotBlockLaterNetworkAdmission(t *testing.T) {
	for _, fd := range []int{-1, 99} {
		t.Run(strconv.Itoa(fd), func(t *testing.T) {
			system := newDescriptors()
			manager := R.NewManager(system)
			receipt := manager.Start(manager.Consume(1, 1, fd), sample, []byte("{}"))
			if receipt.TransferConsumed || receipt.Tun.CloseAttempted || receipt.Cleanup != "complete" || receipt.FailureCode != "TUN_DESCRIPTOR" {
				t.Fatalf("known absent descriptor treated as unknown ownership: %+v", receipt)
			}
			if manager.NetworkBusy() {
				t.Fatal("known absent descriptor prevents later network publication")
			}
			if system.closes[fd] != 0 {
				t.Fatal("attempted to close a descriptor known not to exist")
			}
			// A subsequent real transfer still consumes and closes exactly once.
			next := manager.Start(manager.Consume(2, 2, 9), sample, []byte("{}"))
			if !next.TransferConsumed || next.Cleanup != "complete" || system.closes[9] != 1 || manager.NetworkBusy() {
				t.Fatalf("later valid transfer was blocked or leaked: %+v", next)
			}
		})
	}
}
