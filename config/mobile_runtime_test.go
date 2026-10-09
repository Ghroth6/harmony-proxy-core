package config_test

import (
	"context"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"strings"
	"testing"
)

const trojanCandidateInput = "proxies:\n  - {name: sample, type: trojan, server: 127.0.0.1, port: 443, password: documentation-only, sni: node.example.invalid}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n"

func TestMobileTrojanCandidateConstructsFreshActualAdapter(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(trojanCandidateInput))
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.BuildMobileFixedCandidate(raw)
	if first != nil {
		defer first.Discard(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.BuildMobileFixedCandidate(raw)
	if second != nil {
		defer second.Discard(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	if first.Proxies["sample"].Type() != C.Trojan || first.SharesCandidate(second) {
		t.Fatal("runtime did not independently construct the actual Trojan adapter")
	}
	if err := first.Discard(context.Background()); err != nil || second.CheckCandidate() != nil {
		t.Fatal("discard changed a separately owned Trojan candidate")
	}
}

func TestMobileTrojanCandidateIndependentlyRejectsScopeExpansion(t *testing.T) {
	for _, change := range []struct{ from, to string }{
		{"sni: node.example.invalid", "sni: 192.0.2.1"},
		{"sni: node.example.invalid", "sni: node.example.invalid, skip-cert-verify: 'true'"},
		{"sni: node.example.invalid", "sni: node.example.invalid, dialer-proxy: DIRECT"},
		{"sni: node.example.invalid", "sni: node.example.invalid, network: ws"},
		{"sni: node.example.invalid", "sni: node.example.invalid, cipher: aes-128-gcm"},
		{"sni: node.example.invalid", "sni: node.example.invalid, udp: true"},
		{"127.0.0.1", "example.invalid"},
		{"proxies: [sample]", "proxies: [sample, DIRECT]"},
		{"MATCH,selected", "DOMAIN,example.invalid,selected"},
	} {
		raw, err := config.UnmarshalRawConfig([]byte(strings.Replace(trojanCandidateInput, change.from, change.to, 1)))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := config.BuildMobileFixedCandidate(raw)
		if err == nil {
			t.Fatal("direct candidate call accepted an unaudited Trojan capability")
		}
		if candidate == nil || candidate.Discard(context.Background()) != nil || candidate.CheckCandidate() == nil {
			t.Fatal("rejected candidate lost partial-resource ownership")
		}
	}
}

func TestMobileCandidateRechecksTypedCertificatePolicyWithoutChangingRawBytes(t *testing.T) {
	for _, field := range []string{"", ", skip-cert-verify: false", ", skip-cert-verify: true"} {
		input := strings.Replace(trojanCandidateInput, "sni: node.example.invalid", "sni: node.example.invalid"+field, 1)
		raw, err := config.UnmarshalRawConfig([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := config.BuildMobileFixedCandidate(raw)
		if candidate != nil {
			defer candidate.Discard(context.Background())
		}
		if err != nil || candidate.Proxies["sample"].Type() != C.Trojan {
			t.Fatalf("independent typed certificate policy rejected: %v", err)
		}
		if raw.Proxy[0]["sni"] != "node.example.invalid" {
			t.Fatal("constructor rewrote original SNI")
		}
		if field == ", skip-cert-verify: true" && raw.Proxy[0]["skip-cert-verify"] != true {
			t.Fatal("constructor silently reset explicit policy")
		}
	}
}

func TestMobileFixedCandidateHasIndependentOwnedResources(t *testing.T) {
	input := []byte("proxies:\n  - {name: sample, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: test-only}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n")
	raw, err := config.UnmarshalRawConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.BuildMobileFixedCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.BuildMobileFixedCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Discard(context.Background())
	if first.SharesCandidate(second) || len(first.Rules) != 1 || first.General.IPv6 || first.General.Port != 0 {
		t.Fatal("candidate reused or expanded capabilities")
	}
	if err := first.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.CheckCandidate() == nil || second.CheckCandidate() != nil {
		t.Fatal("discard changed independent runtime candidate")
	}
}
