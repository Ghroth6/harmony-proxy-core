package content_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/mobile/content"
)

func TestYAMLInspectionPreservesUpstreamSOCKSFieldsAndIPv6Endpoint(t *testing.T) {
	input := []byte("proxies:\n - {name: Upstream, type: socks5, server: '::1', port: '1080', username: documentation-user, password: documentation-password, dialer-proxy: Entry, tfo: true, mptcp: true, ip-version: ipv6}\n")
	var attempted atomic.Int32
	receipt := content.NewInspector(func() { attempted.Add(1) }).Inspect("upstream-yaml-node", input)
	if receipt.Category != "inspected" || len(receipt.Entries) != 1 {
		t.Fatalf("original YAML inspection: %s/%s", receipt.Category, receipt.Code)
	}
	entry := receipt.Entries[0]
	if entry.Status != "supported" || entry.Protocol != "socks5" {
		t.Fatalf("upstream SOCKS5 fields must use real construction: %s/%s/%s", entry.Protocol, entry.Status, entry.Code)
	}
	var node map[string]any
	if json.Unmarshal([]byte(entry.NodeJSON), &node) != nil || node["name"] != "selected-node" || node["server"] != "::1" || node["port"] != "1080" || node["username"] != "documentation-user" || node["password"] != "documentation-password" || node["dialer-proxy"] != "Entry" || node["tfo"] != true || node["mptcp"] != true || node["ip-version"] != "ipv6" {
		t.Fatal("canonical node must retain original upstream endpoint, credentials and options")
	}
	if attempted.Load() != 0 {
		t.Fatal("inspection must not dial the chain or its endpoint")
	}
}

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
	if bad.Entries[0].Status != "supported" || !strings.Contains(bad.Entries[0].NodeJSON, "xtls-rprx-vision-obsolete") {
		t.Fatal("URI mapping must preserve the flow accepted by the pinned upstream constructor")
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

func TestTLSNameDefaultsAndIPAddressRemainOriginalWithoutPreparationNetwork(t *testing.T) {
	var attempts atomic.Int32
	inspector := content.NewInspector(func() { attempts.Add(1) })
	for _, item := range []struct{ link, field, value string }{
		{"anytls://documentation@proxy.example:443?sni=", "sni", ""},
		{"hy2://documentation@proxy.example:443?sni=192.0.2.2&insecure=false", "sni", "192.0.2.2"},
	} {
		r := inspector.Inspect("tls-name-original", []byte(item.link))
		if r.Category != "inspected" || len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
			t.Fatalf("engine TLS defaults and IP verification names must be accepted; code=%s", r.Entries[0].Code)
		}
		var node map[string]any
		if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node[item.field] != item.value {
			t.Fatal("explicit empty/default or IP TLS names must retain the original value")
		}
	}
	if attempts.Load() != 0 {
		t.Fatal("TLS preparation must not attempt DNS or physical networking")
	}
}

func TestHTTP2UsesEngineTLSSemanticsWithoutRewritingOriginalTLSFlag(t *testing.T) {
	var attempts atomic.Int32
	const vmess = `{"add":"proxy.example","port":443,"id":"00000000-0000-4000-8000-000000000001","aid":0,"security":"auto","net":"http"}`
	for _, link := range []string{
		"vless://00000000-0000-4000-8000-000000000001@proxy.example:443?type=http&security=none&host=h2.example&path=%2Fh2",
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(vmess)),
	} {
		r := content.NewInspector(func() { attempts.Add(1) }).Inspect("http2-original", []byte(link))
		if len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
			t.Fatalf("HTTP/2 engine construction must preserve and accept the original TLS flag; code=%s", r.Entries[0].Code)
		}
		var node map[string]any
		if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["tls"] != false || node["network"] != "h2" {
			t.Fatal("HTTP/2 transport must not silently rewrite the raw TLS configuration")
		}
	}
	if attempts.Load() != 0 {
		t.Fatal("HTTP/2 static construction must not perform a TLS handshake or DNS")
	}
}

func TestYAMLECHOptionsRemainOwnedAndDoNotQueryDuringPreparation(t *testing.T) {
	var attempts atomic.Int32
	const input = "proxies:\n  - {name: Public, type: vless, server: proxy.example, port: 443, uuid: 00000000-0000-4000-8000-000000000001, tls: true, udp: true, network: ws, ws-opts: {path: /ws, headers: {Host: ws.example}}, ech-opts: {enable: true, query-server-name: ech.example}}\n"
	r := content.NewInspector(func() { attempts.Add(1) }).Inspect("yaml-ech-original", []byte(input))
	if len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
		t.Fatalf("original ECH options must construct through the real adapter; code=%s", r.Entries[0].Code)
	}
	var node map[string]any
	if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil {
		t.Fatal("ECH canonical node must remain JSON")
	}
	ech, _ := node["ech-opts"].(map[string]any)
	if ech["enable"] != true || ech["query-server-name"] != "ech.example" || attempts.Load() != 0 {
		t.Fatal("ECH preparation must preserve its query override without making an HTTPS-record query")
	}
	bad := strings.Replace(input, "query-server-name: ech.example", "unexpected: true", 1)
	if result := content.Inspect("yaml-ech-unknown", []byte(bad)); result.Entries[0].Status != "supported" || !strings.Contains(result.Entries[0].NodeJSON, `"unexpected":true`) {
		t.Fatal("YAML must retain original ECH options and use pinned upstream field semantics")
	}
}

func TestHysteria2PortHoppingRetainsOriginalRangeSpellingAndPinnedSemantics(t *testing.T) {
	var attempts atomic.Int32
	r := content.NewInspector(func() { attempts.Add(1) }).Inspect("hy2-port-hopping", []byte("hy2://documentation%2541@proxy.example:443,8443-8445?sni=tls.example&insecure=0"))
	if len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
		t.Fatalf("valid Hysteria2 port list must reach the engine's actual hopping adapter; code=%s", r.Entries[0].Code)
	}
	var node map[string]any
	if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["port"] != float64(443) || node["ports"] != "443,8443-8445" || node["password"] != "documentation%41" || attempts.Load() != 0 {
		t.Fatal("port hopping must preserve the original bounded ranges and credentials without opening UDP")
	}
	for _, ports := range []string{"443,65536", "8445-8443", "443,,8443"} {
		original := content.Inspect("hy2-original-ports", []byte("hy2://documentation@proxy.example:"+ports))
		var node map[string]any
		if original.Entries[0].Status != "supported" || json.Unmarshal([]byte(original.Entries[0].NodeJSON), &node) != nil || node["ports"] != ports {
			t.Fatal("constructor-accepted port spelling must remain unchanged in the canonical input")
		}
	}
	if zero := content.Inspect("hy2-invalid-authority-port", []byte("hy2://documentation@proxy.example:0-443")); zero.Entries[0].Status == "supported" {
		t.Fatal("URI authority port zero must retain actual URI decoding failure")
	}
}

func TestTCPGeneratorOptionsStayExplicitWithoutActivatingAnotherTransport(t *testing.T) {
	const vmess = `{"v":"2","add":"proxy.example","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","net":"tcp","type":"none","host":"http.example","path":"/inactive","tls":"tls"}`
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	links := []string{
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(vmess)),
		"vless://00000000-0000-4000-8000-000000000001@proxy.example:443?security=reality&type=tcp&fp=chrome&sni=tls.example&pbk=" + key + "&sid=&host=http.example&path=%2Finactive&serviceName=&quicSecurity=none",
	}
	for _, link := range links {
		r := content.Inspect("tcp-generator-fields", []byte(link))
		if len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
			t.Fatalf("known TCP generator fields must stay explicit; code=%s", r.Entries[0].Code)
		}
		var node map[string]any
		if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["network"] != "tcp" {
			t.Fatal("original TCP transport must not turn into HTTP, gRPC or QUIC")
		}
		opts, _ := node["http-opts"].(map[string]any)
		headers, _ := opts["headers"].(map[string]any)
		path, _ := opts["path"].([]any)
		host, _ := headers["Host"].([]any)
		if len(path) != 1 || path[0] != "/inactive" || len(host) != 1 || host[0] != "http.example" {
			t.Fatal("inactive known HTTP options must remain canonical rather than disappear")
		}
		if r.Entries[0].Protocol == "vless" {
			metadata, _ := node["mobile-uri-opts"].(map[string]any)
			if metadata["quicSecurity"] != "none" {
				t.Fatal("explicit no-QUIC generator value must stay bound to actual canonical bytes")
			}
		}
	}
	for _, query := range []string{"&quicSecurity=aes-128-gcm", "&unknownTransportFlag=none"} {
		r := content.Inspect("tcp-generator-unknown", []byte(strings.Replace(links[1], "&quicSecurity=none", query, 1)))
		if r.Entries[0].Status != "unsupported" {
			t.Fatal("active or unknown query parameters must not use a no-op fallback")
		}
	}
}

func TestTrojanExplicitTLSSecurityIsPreservedAndPlaintextIsRejected(t *testing.T) {
	const link = "trojan://documentation@proxy.example:443?security=tls&type=ws&path=%2Fws&host=ws.example&sni=tls.example"
	r := content.Inspect("trojan-explicit-tls", []byte(link))
	if len(r.Entries) != 1 || r.Entries[0].Status != "supported" {
		t.Fatalf("explicit Trojan TLS must use the existing TLS adapter; code=%s", r.Entries[0].Code)
	}
	var node map[string]any
	if json.Unmarshal([]byte(r.Entries[0].NodeJSON), &node) != nil || node["tls"] != true || node["network"] != "ws" {
		t.Fatal("explicit TLS must remain bound to canonical bytes and the selected transport")
	}
	bad := content.Inspect("trojan-plaintext", []byte(strings.Replace(link, "security=tls", "security=none", 1)))
	if bad.Entries[0].Status != "unsupported" {
		t.Fatal("Trojan plaintext cannot silently become TLS")
	}
}

func TestFingerprintInputUsesActualEngineSemanticsWithoutChangingOriginalValue(t *testing.T) {
	const link = "vless://00000000-0000-4000-8000-000000000001@proxy.example:443?security=tls&type=tcp&fp="
	known := content.Inspect("fingerprint-known", []byte(link+"chrome_padding_psk_shuffle"))
	if len(known.Entries) != 1 || known.Entries[0].Status != "supported" {
		t.Fatal("the actual engine fingerprint must not be rejected by a misspelled duplicate allowlist")
	}
	var node map[string]any
	if json.Unmarshal([]byte(known.Entries[0].NodeJSON), &node) != nil || node["client-fingerprint"] != "chrome_padding_psk_shuffle" {
		t.Fatal("supported fingerprint spelling must remain the original actual adapter value")
	}
	bad := content.Inspect("fingerprint-unknown", []byte(link+"documentation-unknown-fingerprint"))
	if bad.Entries[0].Status != "supported" || !strings.Contains(bad.Entries[0].NodeJSON, "documentation-unknown-fingerprint") {
		t.Fatal("unknown fingerprint spelling follows the actual constructor and remains unchanged")
	}
}
