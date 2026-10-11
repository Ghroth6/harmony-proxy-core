package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

// BuildMobileFixedCandidate constructs fresh objects, never validation's
// temporary ones. The mobile driver must gate original YAML fields and obtain
// fixed-scope coverage first. This constructor independently restricts every
// actual semantic constructor it invokes. The returned candidate owns partial
// resources on error too: its caller must Discard it, or transfer via executor.
func BuildMobileFixedCandidate(raw *RawConfig) (cfg *Config, err error) {
	owned := &configresources.Set{}
	cfg = &Config{candidateResources: owned, General: &General{Mode: tunnel.Rule, FindProcessMode: process.FindProcessOff, IPv6: false}, Providers: map[string]P.ProxyProvider{}, RuleProviders: map[string]P.RuleProvider{}, SubRules: map[string][]C.Rule{}}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "CORE_FAILURE"}
		}
	}()
	fail := func() (*Config, error) { return cfg, &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"} }
	if !mobileFixedShape(raw) {
		return fail()
	}
	node := raw.Proxy[0]
	name, _ := node["name"].(string)
	server, _ := node["server"].(string)
	password, _ := node["password"].(string)
	port, portOK := node["port"].(int)
	address, err := netip.ParseAddr(server)
	if name == "" || password == "" || !portOK || port < 1 || port > 65535 || err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return fail()
	}
	switch node["type"] {
	case "trojan":
		if validateMobileTrojan(node, "proxies[0]") != nil {
			return fail()
		}
	case "ss":
		if node["cipher"] != "aes-128-gcm" && node["cipher"] != "chacha20-ietf-poly1305" {
			return fail()
		}
		for key, value := range node {
			switch key {
			case "name", "type", "server", "port", "cipher", "password":
			case "udp":
				if value != false {
					return fail()
				}
			default:
				return fail()
			}
		}
	default:
		return fail()
	}
	proxies, providers, err := parseProxiesInto(raw, owned)
	if err != nil {
		return cfg, &MobileValidationError{Code: "PROXY_OR_GROUP_INVALID", cause: err}
	}
	rules, err := parseRules(raw.Rule, proxies, nil, nil, "rules")
	if err != nil {
		return cfg, &MobileValidationError{Code: "RULE_INVALID", cause: err}
	}
	if len(rules) != 1 {
		return cfg, fmt.Errorf("mobile rule invariant")
	}
	cfg.Proxies, cfg.Providers, cfg.Rules = proxies, providers, rules
	return cfg, nil
}

// Shared by the Trojan static boundary and independent runtime constructor.
// Proxy scalar/protocol checks remain separate from this fixed route shape.
func mobileFixedShape(raw *RawConfig) bool {
	if raw == nil || len(raw.Proxy) != 1 || len(raw.ProxyGroup) != 1 || len(raw.Rule) != 1 || len(raw.ProxyProvider) != 0 || len(raw.RuleProvider) != 0 || len(raw.SubRules) != 0 {
		return false
	}
	node, group := raw.Proxy[0], raw.ProxyGroup[0]
	groupName, ok := group["name"].(string)
	if !ok || groupName == "" || groupName == node["name"] || group["type"] != "select" {
		return false
	}
	for key := range group {
		if key != "name" && key != "type" && key != "proxies" {
			return false
		}
	}
	members, ok := group["proxies"].([]any)
	if !ok || len(members) != 1 || members[0] != node["name"] {
		return false
	}
	parts := strings.Split(raw.Rule[0], ",")
	return len(parts) == 2 && strings.TrimSpace(parts[0]) == "MATCH" && strings.TrimSpace(parts[1]) == groupName
}
