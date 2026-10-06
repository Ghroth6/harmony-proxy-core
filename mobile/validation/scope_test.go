package validation_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/mobile/validation"
)

// Diagnostic descent through the real operation. Phone tests call the same
// application operation; this host evidence does not replace that acceptance.
func TestUnpreparedResourceIsReportedWithoutRequestsWhenNetworkIsAvailable(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("proxies: []\n"))
	}))
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if hits.Swap(0) != 1 {
		t.Fatal("local observation endpoint was not reachable")
	}
	input := []byte(staticConfig + fmt.Sprintf("proxy-providers:\n  unprepared:\n    type: http\n    url: %s\n    path: ./unprepared.yaml\n", server.URL))
	result := validation.Validate("resource-available-network", input)
	if result.Category != "incomplete" || result.Phase != "semantic" {
		t.Fatalf("unprepared resource must remain incomplete: %#v", result)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "RESOURCE_UNAVAILABLE" || result.Diagnostics[0].Field != "/proxy-providers/0/url" {
		t.Fatalf("resource diagnostic must locate the unprepared reference: %#v", result.Diagnostics)
	}
	if hits.Load() != 0 {
		t.Fatal("validation requested the unprepared resource")
	}
}

func TestIgnoredRuleParametersRemainUncovered(t *testing.T) {
	input := []byte(strings.Replace(staticConfig, "DOMAIN,example.com,sample-select", "DOMAIN,example.com,sample-select,no-resolve", 1))
	result := validation.Validate("rule-parameter", input)
	if result.Category != "incomplete" || result.Phase != "semantic" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "UNSUPPORTED_CAPABILITY" || result.Diagnostics[0].Field != "/rules/0" {
		t.Fatalf("extra rule parameters must remain uncovered: %#v", result)
	}
}

func TestCustomFieldTagCannotBeSilentlyDiscarded(t *testing.T) {
	input := []byte(strings.Replace(staticConfig, "proxies:", "!uncovered proxies:", 1))
	result := validation.Validate("custom-tag", input)
	if result.Category != "incomplete" || result.Phase != "semantic" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "UNSUPPORTED_DOCUMENT" || result.Diagnostics[0].Field != "/proxies" {
		t.Fatalf("custom YAML field tags must remain uncovered: %#v", result)
	}
}

func TestResourceReferenceChangesDiagnosisWithoutWritingCandidate(t *testing.T) {
	directory := t.TempDir()
	resource := filepath.Join(directory, "already-present.yaml")
	before := []byte("existing resource must remain unchanged\n")
	if err := os.WriteFile(resource, before, 0600); err != nil {
		t.Fatal(err)
	}
	first := validation.Validate("resource-url", []byte(staticConfig+"proxy-providers:\n  source:\n    type: http\n    url: https://example.invalid/unprepared.yaml\n"))
	second := validation.Validate("resource-file", []byte(staticConfig+fmt.Sprintf("proxy-providers:\n  source:\n    type: file\n    path: %s\n", filepath.ToSlash(resource))))
	if first.Category != "incomplete" || second.Category != "incomplete" || first.InputDigest == second.InputDigest ||
		first.Diagnostics[0].Field != "/proxy-providers/0/url" || second.Diagnostics[0].Field != "/proxy-providers/0/path" {
		t.Fatalf("changing actual references must change the scoped diagnosis: %#v / %#v", first, second)
	}
	after, err := os.ReadFile(resource)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("validation changed the referenced local resource")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("validation persisted a candidate or obtained resource beside the reference")
	}
	encoded, err := json.Marshal(second.Diagnostics)
	if err != nil || strings.Contains(string(encoded), resource) {
		t.Fatal("diagnostics exposed the referenced path")
	}
}

func TestUnsupportedContentIsNotDiscardedByTypedYAML(t *testing.T) {
	cases := []struct{ name, input, code, field string }{
		{"top-field", staticConfig + "untrusted-secret-key: private-value\n", "UNSUPPORTED_FIELD", "/3"},
		{"node-field", strings.Replace(staticConfig, "proxy-groups:", "    plugin: untrusted-secret-value\nproxy-groups:", 1), "UNSUPPORTED_FIELD", "/proxies/0/6"},
		{"cipher", strings.Replace(staticConfig, "aes-128-gcm", "aes-256-gcm", 1), "UNSUPPORTED_CAPABILITY", "/proxies/0/cipher"},
		{"group-provider", strings.Replace(staticConfig, "rules:", "    use: [unprepared]\nrules:", 1), "RESOURCE_UNAVAILABLE", "/proxy-groups/0/use"},
		{"geodata-rule", strings.Replace(staticConfig, "DOMAIN,example.com,sample-select", "GEOIP,ZZ,sample-select", 1), "RESOURCE_UNAVAILABLE", "/rules/0"},
		{"alias", strings.Replace(strings.Replace(staticConfig, "server: 192.0.2.1", "server: &shared 192.0.2.1", 1), "password: documentation-only", "password: *shared", 1), "YAML_ALIAS_UNCHECKED", "/proxies/0/password"},
		{"merge", strings.Replace(strings.Replace(staticConfig, "- name: sample-ss", "- &base\n    name: sample-ss", 1), "proxy-groups:", "  - <<: *base\nproxy-groups:", 1), "YAML_ALIAS_UNCHECKED", "/proxies/1/0"},
		{"extra-document", staticConfig + "---\nproxy-providers: {}\n", "UNSUPPORTED_DOCUMENT", ""},
		{"custom-root", "!uncovered\n" + staticConfig, "UNSUPPORTED_DOCUMENT", ""},
		{"unknown-builtin-root", "!!uncovered\n" + staticConfig, "UNSUPPORTED_DOCUMENT", ""},
		{"unknown-builtin-top-key", strings.Replace(staticConfig, "proxies:", "!!uncovered proxies:", 1), "UNSUPPORTED_DOCUMENT", "/proxies"},
		{"unknown-builtin-node-key", strings.Replace(staticConfig, "server:", "!!uncovered server:", 1), "UNSUPPORTED_DOCUMENT", "/proxies/0/server"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := validation.Validate("unsupported-"+test.name, []byte(test.input))
			if result.Category != "incomplete" || result.Phase != "semantic" || len(result.Diagnostics) == 0 ||
				result.Diagnostics[0].Code != test.code || result.Diagnostics[0].Field != test.field {
				t.Fatalf("uncovered content must be explicit before construction: %#v", result)
			}
			diagnostics, err := json.Marshal(result.Diagnostics)
			if err != nil || strings.Contains(string(diagnostics), "untrusted-secret") || strings.Contains(string(diagnostics), "private-value") {
				t.Fatal("diagnostics echoed untrusted keys or values")
			}
		})
	}
}

func TestCyclicAliasCannotPassOrHang(t *testing.T) {
	result := validation.Validate("cyclic-alias", []byte("proxies: &cycle [*cycle]\n"))
	if result.Category == "pass" || result.Category == "failure" {
		t.Fatalf("cyclic aliases must be rejected or remain incomplete: %#v", result)
	}
}

func TestUnknownTagSpellingsCannotPassStaticValidation(t *testing.T) {
	for _, tag := range []string{"!!uncovered", "!<!!uncovered>", "!<tag:yaml.org,2002:uncovered>", "!<tag:example.invalid,2026:uncovered>"} {
		t.Run(tag, func(t *testing.T) {
			input := []byte(strings.Replace(staticConfig, "server: 192.0.2.1", "server: "+tag+" 192.0.2.1", 1))
			result := validation.Validate("unknown-tag", input)
			if result.Category != "incomplete" || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "UNSUPPORTED_DOCUMENT" || result.Diagnostics[0].Field != "/proxies/0/server" {
				t.Fatalf("unknown tag must remain incomplete at the field: %#v", result)
			}
			encoded, err := json.Marshal(result.Diagnostics)
			if err != nil || strings.Contains(string(encoded), tag) || strings.Contains(string(encoded), "192.0.2.1") {
				t.Fatal("diagnostic exposed the supplied tag or value")
			}
		})
	}
	plain := validation.Validate("plain-tag", []byte(staticConfig))
	standard := validation.Validate("standard-tag", []byte(strings.Replace(staticConfig, "server: 192.0.2.1", "server: !!str 192.0.2.1", 1)))
	if standard.Category != "pass" || standard.InputDigest == plain.InputDigest {
		t.Fatalf("recognized !!str mutation must still pass and identify actual bytes: %#v", standard)
	}
}
