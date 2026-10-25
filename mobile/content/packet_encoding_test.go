package content_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/mobile/content"
)

func TestVMessPacketEncodingPreservesOriginalValuesWithPinnedUpstreamSemantics(t *testing.T) {
	for _, test := range []struct {
		name, field, status, code string
	}{
		{name: "omitted", status: "supported"},
		{name: "empty", field: "packet-encoding: ''", status: "supported"},
		{name: "packetaddr", field: "packet-encoding: packetaddr", status: "supported"},
		{name: "packet-alias", field: "packet-encoding: packet", status: "supported"},
		{name: "xudp", field: "packet-encoding: xudp", status: "supported"},
		{name: "unknown", field: "packet-encoding: documentation-unknown", status: "supported"},
		{name: "wrong-type", field: "packet-encoding: true", status: "invalid", code: "ENTRY_CONSTRUCTION_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			field := ""
			if test.field != "" {
				field = ", " + test.field
			}
			input := []byte("proxies:\n - {name: Documentation, type: vmess, server: 192.0.2.1, port: 443, uuid: 00000000-0000-4000-8000-000000000001, alterId: 0, cipher: auto, udp: true" + field + "}\n")
			var attempts atomic.Int32
			receipt := content.NewInspector(func() { attempts.Add(1) }).Inspect("vmess-packet-encoding", input)
			if receipt.Category != "inspected" || len(receipt.Entries) != 1 {
				t.Fatal("original node must retain one inspectable entry")
			}
			entry := receipt.Entries[0]
			if entry.Status != test.status || entry.Code != test.code {
				t.Errorf("packet encoding must follow the pinned upstream constructor: got %s/%s, want %s/%s", entry.Status, entry.Code, test.status, test.code)
			}
			if test.status == "supported" {
				var canonical map[string]any
				if err := json.Unmarshal([]byte(entry.NodeJSON), &canonical); err != nil {
					t.Fatal("supported node must retain actual canonical bytes")
				}
				value, present := canonical["packet-encoding"]
				if test.name == "omitted" {
					if present {
						t.Error("absent original encoding must remain absent")
					}
				} else {
					expected := map[string]string{"empty": "", "packetaddr": "packetaddr", "packet-alias": "packet", "xudp": "xudp", "unknown": "documentation-unknown"}[test.name]
					if !present || value != expected {
						t.Error("implemented original packet value must survive unchanged")
					}
				}
				if entry.CanonicalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(entry.NodeJSON))) {
					t.Error("success must bind actual canonical bytes")
				}
			} else if entry.NodeJSON != "" || entry.CanonicalDigest != "" {
				t.Error("rejected encoding must not publish canonical candidate bytes")
			}
			if attempts.Load() != 0 {
				t.Error("real node construction and discard must not request network")
			}
		})
	}
	for _, declared := range []bool{false, true} {
		t.Run(fmt.Sprintf("uri-independent-%t", declared), func(t *testing.T) {
			node := map[string]any{"v": "2", "ps": "Documentation", "add": "192.0.2.1", "port": "443", "id": "00000000-0000-4000-8000-000000000001", "aid": "0", "security": "auto", "net": "tcp", "type": "none"}
			if declared {
				node["packet-encoding"] = "packetaddr"
			}
			encoded, err := json.Marshal(node)
			if err != nil {
				t.Fatal(err)
			}
			receipt := content.Inspect("vmess-uri-independent", []byte("vmess://"+base64.RawStdEncoding.EncodeToString(encoded)))
			if len(receipt.Entries) != 1 {
				t.Fatal("URI record must remain inspectable")
			}
			entry := receipt.Entries[0]
			if declared && (entry.Status != "unsupported" || entry.Code != "ENTRY_PARAMETER_UNSUPPORTED" || entry.NodeJSON != "") || !declared && entry.Status != "supported" {
				t.Fatal("canonical YAML fields must not expand the independent original URI whitelist")
			}
		})
	}
}
