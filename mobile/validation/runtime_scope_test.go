package validation_test

import (
	"github.com/metacubex/mihomo/mobile/validation"
	"slices"
	"strings"
	"testing"
)

const runtimeInput = `proxies:
  - name: m1b-node
    type: ss
    server: 192.0.2.1
    port: 8388
    cipher: aes-128-gcm
    password: documentation-only
proxy-groups:
  - name: m1b-proxy
    type: select
    proxies: [m1b-node]
rules:
  - MATCH,m1b-proxy
`

const trojanInput = `proxies:
  - name: m1b-node
    server: 192.0.2.1
    port: 443
    password: documentation-only
    sni: node.example.invalid
    type: trojan
proxy-groups:
  - name: m1b-proxy
    type: select
    proxies: [m1b-node]
rules:
  - MATCH,m1b-proxy
`

func TestSingleTrojanStaticConstructionReturnsAccurateFixedCoverage(t *testing.T) {
	for _, input := range []string{trojanInput, strings.Replace(trojanInput, "    type: trojan", "    udp: false\n    network: tcp\n    skip-cert-verify: false\n    type: trojan", 1)} {
		result := validation.Validate("trojan-fixed", []byte(input))
		if result.Category != "pass" || !slices.Contains(result.Covered, "static-trojan-tcp-tls-sni") || !slices.Contains(result.Covered, "m1b-fixed-ipv4-tcp") || !slices.Contains(result.Covered, "candidate-resources-closed") || slices.Contains(result.Covered, "static-ss-aes-128-gcm") {
			t.Fatalf("single Trojan missing real, accurate coverage: %#v", result)
		}
	}
}

func TestTrojanOriginalFieldsAndExactStaticScopeCannotBeExpanded(t *testing.T) {
	for _, mutation := range []struct{ name, before, after string }{
		{"cipher", "    sni:", "    cipher: aes-128-gcm\n    sni:"},
		{"chain", "    sni:", "    dialer-proxy: DIRECT\n    sni:"},
		{"interface", "    sni:", "    interface-name: test-private-interface\n    sni:"},
		{"mark", "    sni:", "    routing-mark: 1\n    sni:"},
		{"alpn", "    sni:", "    alpn: [h2]\n    sni:"},
		{"fingerprint", "    sni:", "    fingerprint: test-private-fingerprint\n    sni:"},
		{"client fingerprint", "    sni:", "    client-fingerprint: chrome\n    sni:"},
		{"name certificate", "    sni:", "    name-cert-verify: other.example.invalid\n    sni:"},
		{"client certificate", "    sni:", "    certificate: test-private-path\n    sni:"},
		{"client key", "    sni:", "    private-key: test-private-path\n    sni:"},
		{"ECH", "    sni:", "    ech-opts: {enable: true}\n    sni:"},
		{"Reality", "    sni:", "    reality-opts: {}\n    sni:"},
		{"ShadowTLS", "    sni:", "    shadow-tls: {}\n    sni:"},
		{"Restls", "    sni:", "    restls: {}\n    sni:"},
		{"JLS", "    sni:", "    jls-opts: {}\n    sni:"},
		{"WS", "    sni:", "    ws-opts: {}\n    sni:"},
		{"gRPC", "    sni:", "    grpc-opts: {}\n    sni:"},
		{"SS wrapper", "    sni:", "    ss-opts: {}\n    sni:"},
		{"TLS bypass", "    sni:", "    skip-cert-verify: true\n    sni:"},
		{"non TCP", "    sni:", "    network: ws\n    sni:"},
		{"UDP", "    sni:", "    udp: true\n    sni:"},
		{"DNS endpoint", "192.0.2.1", "example.invalid"},
		{"IPv6 endpoint", "192.0.2.1", "2001:db8::1"},
		{"unspecified endpoint", "192.0.2.1", "0.0.0.0"},
		{"multicast endpoint", "192.0.2.1", "224.0.0.1"},
		{"direct choice", "proxies: [m1b-node]", "proxies: [m1b-node, DIRECT]"},
		{"direct route", "MATCH,m1b-proxy", "MATCH,DIRECT"},
		{"DOMAIN", "MATCH,m1b-proxy", "DOMAIN,example.invalid,m1b-proxy"},
		{"two nodes", "proxy-groups:", "  - {name: second, type: trojan, server: 192.0.2.2, port: 443, password: documentation-only, sni: node.example.invalid}\nproxy-groups:"},
		{"mixed transports", "proxy-groups:", "  - {name: second, type: ss, server: 192.0.2.2, port: 443, cipher: aes-128-gcm, password: documentation-only}\nproxy-groups:"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			result := validation.Validate("trojan-scope", []byte(strings.Replace(trojanInput, mutation.before, mutation.after, 1)))
			if result.Category != "incomplete" || slices.Contains(result.Covered, "m1b-fixed-ipv4-tcp") || slices.Contains(result.Covered, "static-trojan-tcp-tls-sni") {
				t.Fatalf("unaudited Trojan scope accepted: %#v", result)
			}
		})
	}
	for _, field := range []string{"sni: node.example.invalid", "network: tcp", "skip-cert-verify: false"} {
		input := strings.Replace(runtimeInput, "    cipher:", "    "+field+"\n    cipher:", 1)
		if result := validation.Validate("ss-fields", []byte(input)); result.Category != "incomplete" {
			t.Fatalf("Trojan whitelist expanded SS fields: %#v", result)
		}
	}
}

func TestTrojanRequiresTypedScalarsAndExplicitValidTLSHostname(t *testing.T) {
	for _, mutation := range []struct{ before, after, field string }{
		{"    sni: node.example.invalid\n", "", "sni"},
		{"sni: node.example.invalid", "sni: ''", "sni"},
		{"sni: node.example.invalid", "sni: true", "sni"},
		{"sni: node.example.invalid", "sni: 192.0.2.1", "sni"},
		{"sni: node.example.invalid", "sni: '*.example.invalid'", "sni"},
		{"sni: node.example.invalid", "sni: 'node example.invalid'", "sni"},
		{"sni: node.example.invalid", "sni: 'node..example.invalid'", "sni"},
		{"sni: node.example.invalid", "sni: '-node.example.invalid'", "sni"},
		{"sni: node.example.invalid", "sni: 'node_.example.invalid'", "sni"},
		{"sni: node.example.invalid", "sni: \"node\\n.example.invalid\"", "sni"},
		{"sni: node.example.invalid", "sni: '" + strings.Repeat("a", 64) + ".example.invalid'", "sni"},
		{"password: documentation-only", "password: ''", "password"},
		{"password: documentation-only", "password: true", "password"},
		{"port: 443", "port: 0", "port"},
		{"port: 443", "port: 65536", "port"},
		{"port: 443", "port: '443'", "port"},
		{"sni: node.example.invalid", "sni: node.example.invalid\n    skip-cert-verify: 'false'", "skip-cert-verify"},
		{"sni: node.example.invalid", "sni: node.example.invalid\n    network: false", "network"},
		{"sni: node.example.invalid", "sni: node.example.invalid\n    udp: 'false'", "udp"},
	} {
		result := validation.Validate("trojan-scalar", []byte(strings.Replace(trojanInput, mutation.before, mutation.after, 1)))
		if result.Category != "invalid" || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "PROXY_INVALID" || result.Diagnostics[0].Field != "proxies[0]."+mutation.field {
			t.Fatalf("invalid Trojan scalar classification: %#v", result)
		}
	}
}

func TestFixedRuntimeCoverageRequiresRealStaticChecks(t *testing.T) {
	result := validation.Validate("fixed-runtime", []byte(runtimeInput))
	if result.Category != "pass" || !slices.Contains(result.Covered, "m1b-fixed-ipv4-tcp") {
		t.Fatalf("fixed runtime sample missing audited coverage: %#v", result)
	}
}

func TestRuntimeCoverageExcludesDifferentRouteOrUnsupportedTransport(t *testing.T) {
	cases := []struct{ name, before, after string }{
		{"DNS endpoint", "192.0.2.1", "example.invalid"},
		{"IPv6 endpoint", "192.0.2.1", "2001:db8::1"},
		{"UDP", "    port: 8388", "    udp: true\n    port: 8388"},
		{"direct choice", "proxies: [m1b-node]", "proxies: [m1b-node, DIRECT]"},
		{"direct rule", "MATCH,m1b-proxy", "MATCH,DIRECT"},
		{"domain rule", "MATCH,m1b-proxy", "DOMAIN,example.com,m1b-proxy"},
		{"empty password", "documentation-only", "''"},
		{"unspecified endpoint", "192.0.2.1", "0.0.0.0"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			result := validation.Validate("scope", []byte(strings.Replace(runtimeInput, item.before, item.after, 1)))
			if slices.Contains(result.Covered, "m1b-fixed-ipv4-tcp") {
				t.Fatalf("unsupported runtime coverage: %#v", result)
			}
		})
	}
}

func TestRuntimeInputFailuresRetainRealClassification(t *testing.T) {
	cases := []struct{ name, input, category, code string }{
		{"format", "proxies: [\n", "invalid", "FORMAT_INVALID"},
		{"group", strings.Replace(runtimeInput, "proxies: [m1b-node]", "proxies: [missing-node]", 1), "invalid", "GROUP_REFERENCE_INVALID"},
		{"rule", strings.Replace(runtimeInput, "MATCH,m1b-proxy", "MATCH,missing-target", 1), "invalid", "RULE_REFERENCE_INVALID"},
		{"resource", runtimeInput + "proxy-providers:\n  x:\n    type: file\n    path: ./missing.yaml\n", "incomplete", "RESOURCE_UNAVAILABLE"},
		{"unsupported", runtimeInput + "dns:\n  enable: true\n", "incomplete", "UNSUPPORTED_FIELD"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			result := validation.Validate("classify", []byte(item.input))
			if result.Category != item.category || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != item.code || slices.Contains(result.Covered, "m1b-fixed-ipv4-tcp") {
				t.Fatalf("wrong classified failure: %#v", result)
			}
		})
	}
}
