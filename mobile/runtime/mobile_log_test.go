//go:build with_gvisor

package runtime_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/mobile/protection"
)

func TestActualTLSFailureAndStopRetainOriginalLogDetails(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	peer := newTrojanPeer(t, "wrong-name")
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	found := false
	for !found {
		select {
		case event := <-sub:
			found = strings.Contains(event.Payload, "certificate") && strings.Contains(event.Payload, "error:")
		case <-deadline.C:
			t.Fatal("actual TLS error text did not reach upstream subscribers")
		}
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarding not joined")
	}
	want := fmt.Sprintf("[Mobile] generation=%d stopped", generation)
	for {
		select {
		case event := <-sub:
			if event.Payload == want {
				return
			}
		case <-deadline.C:
			t.Fatal("normal stop log missing")
		}
	}
}
