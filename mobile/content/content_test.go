package content_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/mobile/content"
)

func TestContentKeepsEveryRecordAndPreservesEncodedShadowsocksPassword(t *testing.T) {
	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:documentation%41@@192.0.2.1:8388")) + "#Example"
	input := []byte(link + "\nnot-a-link\n")
	receipt := content.Inspect("content-first", input)
	if receipt.Category != "inspected" || receipt.Kind != "nodes" || len(receipt.Entries) != 2 {
		t.Fatalf("expected both records to remain inspectable, got category=%s kind=%s entries=%d", receipt.Category, receipt.Kind, len(receipt.Entries))
	}
	first, bad := receipt.Entries[0], receipt.Entries[1]
	const canonical = `{"cipher":"chacha20-ietf-poly1305","name":"selected-node","password":"documentation%41@","port":8388,"server":"192.0.2.1","type":"ss","udp":false}`
	if first.Position != 1 || first.DisplayName != "Example" || first.Protocol != "ss" || first.Status != "supported" || first.NodeJSON != canonical {
		t.Fatal("expected exact original SS parameters and explicit canonical alias")
	}
	if bad.Position != 2 || bad.Status != "invalid" || bad.NodeJSON != "" || bad.Code == "" {
		t.Fatal("expected malformed original record to remain explicitly invalid")
	}
	if again := content.Inspect("content-second", input); again.Entries[0].NodeJSON != canonical || again.Entries[0].EntryDigest != first.EntryDigest || again.InputDigest != receipt.InputDigest {
		t.Fatal("expected deterministic content independent of operation identity")
	}
}

func TestAnyTLSOriginalFieldsConstructWithoutPreparationNetwork(t *testing.T) {
	var attempted atomic.Int32
	inspector := content.NewInspector(func() { attempted.Add(1) })
	receipt := inspector.Inspect("anytls-inspection", []byte("anytls://documentation%2541@proxy.example:443?fp=chrome&type=tcp&insecure=0&sni=tls.example#TLS"))
	if receipt.Category != "inspected" || len(receipt.Entries) != 1 || receipt.Entries[0].Status != "supported" {
		t.Fatal("expected real AnyTLS static construction for preserved supported fields")
	}
	var node map[string]any
	if json.Unmarshal([]byte(receipt.Entries[0].NodeJSON), &node) != nil || node["password"] != "documentation%41" || node["client-fingerprint"] != "chrome" || node["sni"] != "tls.example" || node["skip-cert-verify"] != false {
		t.Fatal("expected single percent decoding and exact AnyTLS TLS policy")
	}
	if attempted.Load() != 0 {
		t.Fatal("expected preparation without DNS, connection or packet attempts")
	}
}

func TestTrojanWebsocketDialectPreservesTransportAndTLS(t *testing.T) {
	var attempts atomic.Int32
	r := content.NewInspector(func() { attempts.Add(1) }).Inspect("trojan-ws", []byte("trojan://documentation%2541@proxy.example:443?ws=true&wspath=%2Fws%3Fed%3D256&host=ws.example&sni=tls.example&allowInsecure=false&fp=chrome#WS"))
	if r.Category != "inspected" || len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
		t.Fatal("expected real Trojan websocket construction from the original dialect")
	}
	var node map[string]any
	if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["password"] != "documentation%41" || node["network"] != "ws" || node["skip-cert-verify"] != false {
		t.Fatal("expected preserved credentials, websocket and certificate policy")
	}
	ws, _ := node["ws-opts"].(map[string]any)
	headers, _ := ws["headers"].(map[string]any)
	if ws["path"] != "/ws?ed=256" || headers["Host"] != "ws.example" || node["sni"] != "tls.example" || attempts.Load() != 0 {
		t.Fatal("expected exact websocket options and no preparation network")
	}
}

func TestVLESSRealityFieldsArePreservedAndUnsupportedFlowIsExplicit(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	const prefix = "vless://00000000-0000-4000-8000-000000000001@proxy.example:443?type=tcp&security=reality&encryption=none&sni=tls.example&fp=chrome&flow=xtls-rprx-vision&sid=0102&pbk="
	r := content.Inspect("vless-reality", []byte(prefix+key+"#Reality\n"+prefix+key+"&surprise=ignored"))
	if r.Category != "inspected" || len(r.Entries) != 2 || r.Entries[0].Status != "supported" || r.Entries[1].Status != "unsupported" || r.Entries[1].NodeJSON != "" {
		t.Fatal("expected exact supported Reality entry and explicit unmapped parameter")
	}
	var node map[string]any
	if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil {
		t.Fatal("canonical node is not JSON")
	}
	reality, _ := node["reality-opts"].(map[string]any)
	if node["tls"] != true || node["servername"] != "tls.example" || node["flow"] != "xtls-rprx-vision" || node["encryption"] != "none" || reality["public-key"] != key || reality["short-id"] != "0102" {
		t.Fatal("expected original Reality, TLS and flow values without truncation")
	}
	bad := content.Inspect("vless-flow", []byte("vless://00000000-0000-4000-8000-000000000001@proxy.example:443?flow=xtls-rprx-vision-obsolete&type=tcp"))
	if bad.Entries[0].Status == "supported" {
		t.Fatal("a flow that upstream truncates cannot be silently accepted")
	}
}

func TestVMessJSONPreservesCipherTLSAndWebsocketWithoutDefaultsDroppingFields(t *testing.T) {
	const original = `{"v":"2","ps":"JSON","add":"proxy.example","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","security":"auto","net":"ws","type":"none","host":"ws.example","path":"/ws","tls":"tls","sni":"tls.example","allowInsecure":false,"fp":"chrome"}`
	r := content.Inspect("vmess-json", []byte("vmess://"+base64.RawStdEncoding.EncodeToString([]byte(original))))
	if r.Category != "inspected" || len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
		t.Fatal("expected real VMess JSON construction")
	}
	var node map[string]any
	_ = json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node)
	if node["cipher"] != "auto" || node["tls"] != true || node["skip-cert-verify"] != false || node["network"] != "ws" || node["alterId"] != float64(0) {
		t.Fatal("VMess original security policy was dropped")
	}
	duplicate := `{"add":"proxy.example","add":"other.example"}`
	bad := content.Inspect("vmess-duplicate", []byte("vmess://"+base64.RawStdEncoding.EncodeToString([]byte(duplicate))))
	if bad.Entries[0].Status != "invalid" || bad.Entries[0].Code != "ENTRY_PARAMETER_DUPLICATE" {
		t.Fatal("duplicate JSON fields must remain invalid")
	}
}

func TestHysteria2LazyConstructionHasNoPreparationDatagramOrDNS(t *testing.T) {
	var attempts atomic.Int32
	r := content.NewInspector(func() { attempts.Add(1) }).Inspect("hy2-inspection", []byte("hy2://documentation%2541@proxy.example:443?sni=tls.example&insecure=0&obfs=salamander&obfs-password=public%2541&alpn=h3#QUIC"))
	if r.Category != "inspected" || len(r.Entries) != 1 || r.Entries[0].Protocol != "hysteria2" || r.Entries[0].Status != "supported" {
		t.Fatal("expected real owned Hysteria2 constructor and cleanup")
	}
	var node map[string]any
	_ = json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node)
	if node["password"] != "documentation%41" || node["obfs"] != "salamander" || node["obfs-password"] != "public%41" || node["skip-cert-verify"] != false || attempts.Load() != 0 {
		t.Fatal("expected exact QUIC fields without preparation networking")
	}
}

func TestYAMLInspectionKeepsSourcePolicyAndAllOriginalPositions(t *testing.T) {
	input := []byte("dns: {enable: true, nameserver: [192.0.2.53]}\nproxies:\n - {name: Duplicate, type: anytls, server: proxy.example, port: 443, password: 'documentation%41', udp: true}\n - {name: Duplicate, type: unfamiliar, server: proxy.example, port: 443}\n - {name: broken, type: ss, cipher: aes-128-gcm, server: proxy.example, port: 443, password: a, password: b}\nproxy-groups: [{name: route, type: select, proxies: [Duplicate]}]\nrules: [MATCH,route]\n")
	r := content.Inspect("yaml-inspection", input)
	if r.Kind != "yaml" || r.Category != "inspected" || len(r.Entries) != 3 || r.Entries[0].Status != "supported" || r.Entries[1].Status != "unsupported" || r.Entries[2].Status != "invalid" {
		t.Fatal("expected original YAML identity and every entry position including unsupported/duplicate fields")
	}
	if r.Entries[0].DisplayName != "Duplicate" || r.Entries[1].DisplayName != "Duplicate" || r.Entries[0].Position != 1 || r.Entries[1].Position != 2 || r.Entries[2].Code != "ENTRY_PARAMETER_DUPLICATE" {
		t.Fatal("entries must not be merged or silently dropped")
	}
	var node map[string]any
	_ = json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node)
	if node["password"] != "documentation%41" || node["name"] != "selected-node" || node["udp"] != true {
		t.Fatal("YAML canonical node parameters were changed")
	}
	links := "anytls://documentation@proxy.example:443\nunknown://record"
	b := content.Inspect("base64-inspection", []byte(base64.StdEncoding.EncodeToString([]byte(links))))
	if b.Kind != "base64-nodes" || b.Category != "inspected" || len(b.Entries) != 2 || b.Entries[1].Status != "unsupported" {
		t.Fatal("Base64 input must keep its original kind and all decoded entries")
	}
}

func TestTransportVariantsStayExplicitAndDeterministic(t *testing.T) {
	const prefix = "vless://00000000-0000-4000-8000-000000000001@proxy.example:443?security=tls&sni=tls.example&"
	for _, item := range []struct{ query, network, option, key, expected string }{
		{"type=grpc&serviceName=public-service&mode=gun", "grpc", "grpc-opts", "grpc-service-name", "public-service"},
		{"type=xhttp&host=transport.example&path=%2Fsplit&mode=auto", "xhttp", "xhttp-opts", "path", "/split"},
		{"type=http&host=transport.example&path=%2Fh2", "h2", "h2-opts", "path", "/h2"},
	} {
		r := content.Inspect("transport-variants", []byte(prefix+item.query))
		if r.Entries[0].Status != "supported" {
			t.Fatalf("expected supported %s transport", item.network)
		}
		var node map[string]any
		_ = json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node)
		options, _ := node[item.option].(map[string]any)
		if node["network"] != item.network || options[item.key] != item.expected {
			t.Fatal("transport fields changed or disappeared")
		}
	}
}

func TestShadowsocksOriginalCredentialEncodingBranchesAndUDP(t *testing.T) {
	for _, password := range []string{"documentation%41", "documentation%", "documentation@"} {
		for _, link := range []string{
			"ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:"+password+"@192.0.2.1:8388")),
			"ss://" + base64.RawStdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:"+password)) + "@192.0.2.1:8388",
		} {
			r := content.Inspect("ss-encoding", []byte(link))
			var node map[string]any
			if r.Entries[0].Status != "supported" || json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["password"] != password {
				t.Fatal("Base64 credentials must stay literal after decoding their original representation")
			}
		}
	}
	r := content.Inspect("ss-plaintext", []byte("ss://chacha20-ietf-poly1305:documentation%2541@proxy.example:8388?udp=true"))
	var node map[string]any
	if r.Entries[0].Status != "supported" || json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["password"] != "documentation%41" || node["udp"] != true {
		t.Fatal("plaintext credentials require exactly one URI decoding and explicit UDP preservation")
	}
}

func TestContentRejectsMalformedUnicodeAndWholeCanonicalBudgetExcess(t *testing.T) {
	const malformed = `{"add":"proxy.example","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","net":"ws","host":"ws.example","path":"/public\uD800","tls":"tls"}`
	bad := content.Inspect("vmess-unicode", []byte("vmess://"+base64.RawStdEncoding.EncodeToString([]byte(malformed))))
	if bad.Category != "inspected" || len(bad.Entries) != 1 || bad.Entries[0].Status != "invalid" || bad.Entries[0].NodeJSON != "" {
		t.Error("invalid Unicode escapes must not be silently replaced in transport parameters")
	}
	input := []byte("ss://chacha20-ietf-poly1305:" + strings.Repeat("%00", 175000) + "@192.0.2.1:8388")
	if len(input) > content.MaxInputBytes {
		t.Fatal("synthetic raw input must fit the raw budget")
	}
	oversize := content.Inspect("canonical-budget", input)
	if oversize.Category != "failure" || oversize.Code != "CONTENT_NODE_BOUNDS" || len(oversize.Entries) != 0 {
		t.Fatal("canonical expansion over budget must reject the whole inspection without truncation")
	}
}
