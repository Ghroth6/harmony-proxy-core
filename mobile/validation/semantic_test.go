package validation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/validation"
)

func TestStaticConfigurationPassesRealSemanticValidation(t *testing.T) {
	result := validation.Validate("semantic-valid", []byte(staticConfig))
	if result.Category != "pass" || result.Phase != "semantic" {
		t.Fatalf("self-contained static configuration must pass semantics: %#v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("valid configuration returned diagnostics: %#v", result)
	}
}

func TestMissingRuleTargetIsRejectedWithoutEchoingInputAndRetryPasses(t *testing.T) {
	broken := strings.Replace(staticConfig, "DOMAIN,example.com,sample-select", "DOMAIN,example.com,missing-secret-target", 1)
	result := validation.Validate("semantic-rule-invalid", []byte(broken))
	if result.Category != "invalid" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "RULE_REFERENCE_INVALID" || result.Diagnostics[0].Field != "rules[0]" {
		t.Fatalf("missing rule target must return its core reference diagnostic: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "missing-secret-target") || strings.Contains(string(encoded), "documentation-only") {
		t.Fatal("receipt must not echo configuration values or credentials")
	}
	retry := validation.Validate("semantic-rule-corrected", []byte(strings.Replace(broken, "missing-secret-target", "sample-select", 1)))
	if retry.Category != "pass" || retry.InputDigest == result.InputDigest {
		t.Fatalf("corrected actual bytes must pass the same operation: %#v", retry)
	}
}

func TestMissingGroupMemberIsRejectedAndCorrectedBytesPass(t *testing.T) {
	broken := strings.Replace(staticConfig, "proxies: [sample-ss, DIRECT]", "proxies: [missing-node, DIRECT]", 1)
	result := validation.Validate("semantic-group-invalid", []byte(broken))
	if result.Category != "invalid" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "GROUP_REFERENCE_INVALID" || result.Diagnostics[0].Field != "proxy-groups[0].proxies" {
		t.Fatalf("missing group member must return its core reference diagnostic: %#v", result)
	}
	retry := validation.Validate("semantic-group-corrected", []byte(strings.Replace(broken, "missing-node", "sample-ss", 1)))
	if retry.Category != "pass" || retry.InputDigest == result.InputDigest {
		t.Fatalf("corrected actual bytes must pass the same operation: %#v", retry)
	}
}

func TestStaticNodeRequiresValidServerPortAndRequiredFields(t *testing.T) {
	mutations := []struct {
		name, from, to, field string
	}{
		{"empty-server", "server: 192.0.2.1", "server: ''", "proxies[0].server"},
		{"zero-port", "port: 8388", "port: 0", "proxies[0].port"},
		{"negative-port", "port: 8388", "port: -1", "proxies[0].port"},
		{"out-of-range-port", "port: 8388", "port: 65536", "proxies[0].port"},
		{"fractional-port", "port: 8388", "port: 8388.5", "proxies[0].port"},
		{"missing-password", "    password: documentation-only\n", "", "proxies[0].password"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			input := strings.Replace(staticConfig, mutation.from, mutation.to, 1)
			result := validation.Validate("static-node-"+mutation.name, []byte(input))
			if result.Category != "invalid" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "PROXY_INVALID" || result.Diagnostics[0].Field != mutation.field {
				t.Fatalf("invalid static node field must not pass: %#v", result)
			}
		})
	}
}
