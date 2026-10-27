//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Socket adapter boundary only; all Tracker creation, registry traversal,
// generation checks and runtime receipt serialization remain production code.
type readableSocket struct {
	unrelatedQueryConn
	chain C.Chain
	kind  C.AdapterType
}

func (c *readableSocket) Chains() C.Chain           { return c.chain }
func (c *readableSocket) EgressType() C.AdapterType { return c.kind }

func wireNodes(value any) int {
	count := 1
	switch value := value.(type) {
	case map[string]any:
		for _, child := range value {
			count += wireNodes(child)
		}
	case []any:
		for _, child := range value {
			count += wireNodes(child)
		}
	}
	return count
}

func TestRuntimeReadableShortestLargeRegistryRespectsBothProductionDecoderBudgets(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	manager := newNodeManager(t, newPacketDescriptors(), generation)
	t.Cleanup(func() { manager.Stop(generation) })
	if started := manager.Start(manager.Consume(generation, 1, 9), fixed, preparedNodeRequest(t, fixed, generation)); started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	root, err := forwarding.Context(generation)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2600; index++ {
		metadata := &C.Metadata{Type: C.TUN, NetWork: C.TCP, ForwardingGeneration: generation, RequestContext: root, DstPort: 1}
		tracker := statistic.NewTCPTracker(&readableSocket{chain: C.Chain{"a", "b", "c", "d", "e", "f", "g", "h"}, kind: C.Direct}, statistic.DefaultManager, metadata, nil, 0, 0, false)
		t.Cleanup(func() { _ = tracker.Close() })
	}
	receipt := manager.Query(generation, 1)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err = json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	nodes := wireNodes(value)
	t.Logf("OBS52_LARGE_RECEIPT:%s", encoded)
	t.Logf("OBS52_LARGE_BUDGET bytes=%d nodes=%d returned=%d omitted=%d", len(encoded), nodes, len(receipt.Connections), receipt.ConnectionSnapshot.ActiveOmitted)
	if len(encoded) > R.MaxOutputBytes || nodes > 65536 || receipt.ConnectionSnapshot.Active != 2600 || uint64(len(receipt.Connections))+receipt.ConnectionSnapshot.ActiveOmitted != 2600 || !receipt.ForwardingActive {
		t.Fatalf("actual readable registry exceeded a production decoder budget: bytes=%d nodes=%d", len(encoded), nodes)
	}
	if len(receipt.Connections) == 0 || receipt.ConnectionSnapshot.ActiveOmitted == 0 {
		t.Fatal("bounded readable observations must retain real values and report omitted active connections")
	}
}

func TestRuntimeReadableProjectionBoundsDoNotInventLabelsOrEgress(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	manager := newNodeManager(t, newPacketDescriptors(), generation)
	t.Cleanup(func() { manager.Stop(generation) })
	if started := manager.Start(manager.Consume(generation, 1, 9), fixed, preparedNodeRequest(t, fixed, generation)); started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	root, err := forwarding.Context(generation)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host          string
		chain         C.Chain
		kind          C.AdapterType
		state, egress string
	}{
		{"例子.test", C.Chain{"节点 🧭 \"引用\"\\路径\n第二行", "选择组"}, C.Shadowsocks, "available", "shadowsocks"},
		{"", C.Chain{"DIRECT"}, C.AdapterType(10000), "available", "unknown"},
		{strings.Repeat("界", 342), C.Chain{"leaf", "group"}, C.Direct, "limited", "unknown"},
		{"", C.Chain{strings.Repeat("界", 86), "group"}, C.Direct, "limited", "unknown"},
		{"", C.Chain{"\xff", "group"}, C.Direct, "limited", "unknown"},
		{"", C.Chain{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, C.Direct, "limited", "unknown"},
	} {
		tracker := statistic.NewTCPTracker(&readableSocket{chain: test.chain, kind: test.kind}, statistic.DefaultManager, &C.Metadata{Type: C.TUN, NetWork: C.TCP, ForwardingGeneration: generation, RequestContext: root, Host: test.host, DstPort: 443}, nil, 11, 22, false)
		receipt := manager.Query(generation, 1)
		var got R.ConnectionReadable
		for _, connection := range receipt.Connections {
			if connection.ID == tracker.ID() {
				got = connection.Readable
			}
		}
		if got.State != test.state || got.OutboundType != test.egress || got.SchemaVersion != 1 {
			t.Fatalf("readable state: %+v", got)
		}
		if test.state == "available" {
			if got.Host != test.host || len(got.Chain) != len(test.chain) || got.Chain[0] != test.chain[0] {
				t.Fatal("readable values changed")
			}
		} else if got.Host != "" || got.RulePayload != "" || len(got.Chain) != 0 {
			t.Fatal("partial or invalid label escaped")
		}
		_ = tracker.Close()
	}
	if stopped := manager.Stop(generation); stopped.Cleanup != "complete" {
		t.Fatal(stopped.FailureCode)
	}
}
