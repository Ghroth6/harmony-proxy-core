package network_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/mobile/network"
)

func snapshot(generation uint64) []byte {
	return []byte(fmt.Sprintf(`{"schemaVersion":1,"generation":%d,"networkId":17,"vpn":false,"online":true,"dns":["192.0.2.53"],"interfaces":[{"name":"synthetic0","index":0,"mtu":1500,"up":true,"addresses":["192.0.2.10/24"],"routes":[{"destination":"0.0.0.0/0","gateway":"192.0.2.1"}]}]}`, generation))
}
func next() uint64 { value, _ := platformnetwork.Current(); return value.Generation + 1 }

func TestNetworkSubmissionValidatesThenJoinsPreviousEpochBeforePublishing(t *testing.T) {
	controller := network.NewController(func() bool { return false })
	gen := next()
	first := controller.Submit("network-first", snapshot(gen))
	if first.Category != "published" || first.Generation != gen {
		t.Fatal("valid submitted underlying network was not published")
	}
	observed, enabled := platformnetwork.Current()
	if !enabled || observed.Generation != gen || len(observed.DNS) != 1 || observed.DNS[0] != "192.0.2.53:53" {
		t.Fatal("receipt must correspond to actual atomic copied and normalized snapshot")
	}
	ctx, finish, err := forwarding.AcquireManagementNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan network.Receipt, 1)
	go func() { result <- controller.Submit("network-next", snapshot(gen+1)) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old management epoch was not canceled")
	}
	if current, _ := platformnetwork.Current(); current.Generation != gen {
		t.Fatal("new snapshot published before old work completed")
	}
	select {
	case <-result:
		t.Fatal("submission returned before joining old epoch")
	default:
	}
	finish()
	if second := <-result; second.Category != "published" || second.Generation != gen+1 {
		t.Fatal("joined transition did not publish new snapshot")
	}
	if stale := controller.Submit("network-stale", snapshot(gen)); stale.Category != "stale" {
		t.Fatal("stale snapshot must not republish an old path")
	}
	for _, input := range []string{
		strings.Replace(string(snapshot(gen+2)), `"vpn":false`, `"vpn":true`, 1),
		strings.Replace(string(snapshot(gen+2)), `"networkId":17`, `"networkId":17,"networkId":18`, 1),
		strings.Replace(string(snapshot(gen+2)), `"online":true`, `"online":true,"unknown":0`, 1),
		strings.Replace(string(snapshot(gen+2)), `"up":true`, `"up":null`, 1),
	} {
		if rejected := controller.Submit("network-invalid", []byte(input)); rejected.Category != "invalid" {
			t.Fatal("invalid/ambiguous underlying network accepted")
		}
	}
	busy := network.NewController(func() bool { return true }).Submit("network-busy", snapshot(gen+2))
	if busy.Category != "busy" {
		t.Fatal("active or pending runtime must prevent path replacement")
	}
}
