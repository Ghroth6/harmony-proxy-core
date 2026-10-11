package config

import (
	"context"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

// Builtins must obey the same preparation fence as remote adapters. Groups
// borrow these wrapped objects rather than retaining an unfenced DIRECT.
type mobilePolicyBuiltin struct {
	C.ProxyAdapter
	fence *mobileCandidateDialer
}

func (b *mobilePolicyBuiltin) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	ctx, err := b.fence.context(ctx)
	if err != nil {
		return nil, err
	}
	return b.ProxyAdapter.DialContext(ctx, metadata)
}
func (b *mobilePolicyBuiltin) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	ctx, err := b.fence.context(ctx)
	if err != nil {
		return nil, err
	}
	return b.ProxyAdapter.ListenPacketContext(ctx, metadata)
}

// BuildMobilePolicyCandidate is independent of full-parser side effects.
// Resources are supplied as verified immutable bytes by mobile/policy. The
// original rules/groups/general settings remain distinct from selected MATCH.
func BuildMobilePolicyCandidate(raw *RawConfig, prepared contract.PreparedContext, preferences map[string]string) (cfg *Config, err error) {
	owned := &configresources.Set{}
	fence := &mobileCandidateDialer{physical: dialer.NewDialer(dialer.WithOnlySingleStack(!raw.IPv6), dialer.WithResolver(resolver.SystemResolver))}
	cfg = &Config{candidateResources: owned, mobileNetwork: fence, mobilePolicy: &prepared, Providers: map[string]P.ProxyProvider{}, RuleProviders: map[string]P.RuleProvider{}, SubRules: map[string][]C.Rule{}}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "POLICY_CONSTRUCTION_FAILED"}
		}
		if fence.attempts.Load() != 0 {
			err = &MobileValidationError{Code: "PREPARATION_NETWORK_FORBIDDEN"}
		}
	}()
	if raw.DNS.Enable {
		return cfg, &MobileValidationError{Code: "POLICY_DNS_RUNTIME_NOT_READY"}
	}
	if len(raw.RuleProvider) != 0 || len(raw.ProxyProvider) != 0 {
		return cfg, &MobileValidationError{Code: "POLICY_RESOURCE_RUNTIME_NOT_READY"}
	}
	for _, node := range raw.Proxy {
		if err = MobileNodeFields(node); err != nil {
			return cfg, err
		}
	}
	cfg.General, err = parseGeneral(raw)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_GENERAL_INVALID"}
	}
	cfg.Profile = &Profile{StoreSelected: raw.Profile.StoreSelected, StoreFakeIP: raw.Profile.StoreFakeIP}
	cfg.Hosts, err = parseHosts(raw)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_HOSTS_INVALID"}
	}
	cfg.Proxies, cfg.Providers, err = parseProxiesWithBuiltins(raw, owned, func(a C.ProxyAdapter) C.ProxyAdapter { return &mobilePolicyBuiltin{ProxyAdapter: a, fence: fence} }, adapter.WithDialerForAPI(fence))
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_PROXY_OR_GROUP_INVALID"}
	}
	for group, name := range preferences {
		proxy := cfg.Proxies[group]
		if proxy == nil {
			return cfg, &MobileValidationError{Code: "POLICY_GROUP_PREFERENCE_INVALID"}
		}
		selector, ok := proxy.Adapter().(interface{ Set(string) error })
		if !ok || selector.Set(name) != nil {
			return cfg, &MobileValidationError{Code: "POLICY_GROUP_PREFERENCE_INVALID"}
		}
	}
	cfg.SubRules, err = parseSubRules(raw, cfg.Proxies, cfg.RuleProviders)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_RULE_INVALID"}
	}
	cfg.Rules, err = parseRules(raw.Rule, cfg.Proxies, cfg.RuleProviders, cfg.SubRules, "rules")
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_RULE_INVALID"}
	}
	return cfg, nil
}

// MobilePolicyContext returns the immutable accepted value identity. It is not
// a resource downloader and does not mutate the application subscription raw.
func (c *Config) MobilePolicyContext() (contract.PreparedContext, bool) {
	if c == nil || c.mobilePolicy == nil {
		return contract.PreparedContext{}, false
	}
	return *c.mobilePolicy, true
}
