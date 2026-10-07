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
