package config

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

type MobilePolicyServices interface {
	ActivateScheduled(context.Context) error
	Cancel()
	Wait(context.Context) error
}
type MobilePolicyResources struct {
	RuleProviders map[string]P.RuleProvider
	ParseRule     RC.ParseRuleFunc
	Services      MobilePolicyServices
	FakeIPState   *fakeip.ScopedPersistence
}

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
func BuildMobilePolicyCandidate(raw *RawConfig, prepared contract.PreparedContext, preferences map[string]string, inputs ...*MobilePolicyResources) (cfg *Config, err error) {
	prepared = contract.ClonePrepared(prepared)
	owned := &configresources.Set{}
	fence := &mobileCandidateDialer{physical: dialer.NewDialer(dialer.WithOnlySingleStack(!raw.IPv6), dialer.WithResolver(resolver.SystemResolver))}
	cfg = &Config{candidateResources: owned, mobileNetwork: fence, mobilePolicy: &prepared, Providers: map[string]P.ProxyProvider{}, RuleProviders: map[string]P.RuleProvider{}, SubRules: map[string][]C.Rule{}}
	parse := rules.ScopedParser(cfg.RuleProviders, nil)
	if len(inputs) == 1 && inputs[0] != nil {
		cfg.mobilePolicyResources = inputs[0]
		cfg.RuleProviders = inputs[0].RuleProviders
		parse = inputs[0].ParseRule
		for _, provider := range cfg.RuleProviders {
			owned.AddProvider(provider)
		}
		if inputs[0].FakeIPState != nil {
			inputs[0].FakeIPState.SetFailureHandler(func() {
				cfg.CancelMobilePolicyServices()
				if cfg.mobilePolicyFailure != nil {
					cfg.mobilePolicyFailure("POLICY_FAKEIP_STATE_FAILED")
				}
			})
		}
	}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "POLICY_CONSTRUCTION_FAILED"}
		}
		if fence.attempts.Load() != 0 {
			err = &MobileValidationError{Code: "PREPARATION_NETWORK_FORBIDDEN"}
		}
	}()
	if len(raw.ProxyProvider) != 0 || len(raw.RuleProvider) != len(cfg.RuleProviders) {
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
	cfg.Profile = &Profile{StoreSelected: raw.Profile.StoreSelected, StoreFakeIP: raw.Profile.StoreFakeIP, Tracing: raw.Profile.Tracing}
	cfg.Sniffer, err = parseSniffer(raw.Sniffer, cfg.RuleProviders, parse)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_SNIFFER_INVALID"}
	}
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
	cfg.SubRules, err = parseSubRulesWith(raw, cfg.Proxies, cfg.RuleProviders, parse)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_RULE_INVALID"}
	}
	cfg.Rules, err = parseRulesWith(raw.Rule, cfg.Proxies, cfg.RuleProviders, cfg.SubRules, "rules", parse)
	if err != nil {
		return cfg, &MobileValidationError{Code: "POLICY_RULE_INVALID"}
	}
	if raw.DNS.Enable {
		cfg.DNS, err = parseDNS(raw, cfg.RuleProviders, cfg.mobilePolicyResources)
		if err != nil {
			return cfg, &MobileValidationError{Code: "POLICY_DNS_INVALID"}
		}
		cfg.mobileDNS = buildMobileDNS(cfg.DNS, raw.IPv6)
	} else {
		cfg.mobileDNS = buildMobileSystemBootstrap(raw.IPv6)
	}
	// Capture this candidate's bootstrap policy, rather than the mutable
	// published resolver or the system resolver forced by selected-node mode.
	// The shared fence remains closed throughout construction.
	bootstrap, _ := cfg.MobileNodeResolvers()
	fence.physical = dialer.NewDialer(dialer.WithOnlySingleStack(!raw.IPv6), dialer.WithResolver(bootstrap))
	return cfg, nil
}

// MobilePolicyContext returns the immutable accepted value identity. It is not
// a resource downloader and does not mutate the application subscription raw.
func (c *Config) MobilePolicyContext() (contract.PreparedContext, bool) {
	if c == nil || c.mobilePolicy == nil {
		return contract.PreparedContext{}, false
	}
	return contract.ClonePrepared(*c.mobilePolicy), true
}

func (c *Config) ActivateMobilePolicyResources(root context.Context) error {
	if c == nil || c.mobilePolicy == nil || c.mobileNetwork == nil {
		return &MobileValidationError{Code: "POLICY_IDENTITY_INVALID"}
	}
	if err := c.CheckCandidate(); err != nil {
		return err
	}
	if c.mobilePolicyResources == nil || c.mobilePolicyResources.Services == nil {
		return nil
	}
	scope, err := forwarding.Context(c.mobileNetwork.generation.Load())
	if err != nil {
		return err
	}
	return c.mobilePolicyResources.Services.ActivateScheduled(forwarding.Bind(root, scope))
}

func (c *Config) CancelMobilePolicyServices() {
	if c != nil && c.mobilePolicy != nil {
		for _, provider := range c.Providers {
			if owner, ok := provider.(interface{ Cancel() }); ok {
				owner.Cancel()
			}
		}
	}
	if c != nil && c.mobileDNS != nil {
		c.mobileDNS.owner.Cancel()
	}
	if c != nil && c.mobilePolicyResources != nil && c.mobilePolicyResources.Services != nil {
		c.mobilePolicyResources.Services.Cancel()
	}
}
func (c *Config) WaitMobilePolicyServices(ctx context.Context) error {
	var errs []error
	if c != nil && c.mobilePolicy != nil {
		for _, provider := range c.Providers {
			if owner, ok := provider.(interface{ Wait(context.Context) error }); ok {
				errs = append(errs, owner.Wait(ctx))
			}
		}
	}
	if c != nil && c.mobileDNS != nil {
		if err := c.mobileDNS.owner.Wait(ctx); err != nil {
			// The DB is borrowed by real DNS handlers. A timed-out DNS wait must
			// not close that store or release the engine root underneath them.
			return errors.Join(append(errs, err)...)
		}
	}
	if c != nil && c.mobilePolicyResources != nil && c.mobilePolicyResources.Services != nil {
		errs = append(errs, c.mobilePolicyResources.Services.Wait(ctx))
	}
	return errors.Join(errs...)
}

// BindMobilePolicyFailure reports sticky state failures to the actual runtime
// owner. It is installed before activation; static callers need no handler.
func (c *Config) BindMobilePolicyFailure(handler func(string)) {
	c.mobilePolicyFailure = handler
}

// A mobile publication binds health checks but starts none. Their timers and
// retry/selection requests begin only after the entry explicitly goes running.
func (c *Config) BindMobilePolicyHealthChecks(root context.Context) error {
	if generation := c.mobileNetwork.generation.Load(); generation > 0 {
		scope, err := forwarding.Context(generation)
		if err != nil {
			return err
		}
		root = forwarding.Bind(root, scope)
	}
	for _, provider := range c.Providers {
		owner, ok := provider.(interface{ BindHealthCheckContext(context.Context) error })
		if !ok || provider.VehicleType() != P.Compatible {
			return errors.New("POLICY_HEALTHCHECK_OWNER_INVALID")
		}
		if err := owner.BindHealthCheckContext(root); err != nil {
			return err
		}
	}
	return nil
}
func (c *Config) ActivateMobilePolicyHealthChecks() error {
	if c.mobileNetwork == nil || c.mobileNetwork.generation.Load() == 0 {
		// Static publication callers may activate an entry with no scheduled
		// health work. They still cannot open an actual outbound candidate fence.
		for _, provider := range c.Providers {
			if owner, ok := provider.(interface{ HealthCheckEnabled() bool }); !ok || owner.HealthCheckEnabled() {
				return errors.New("POLICY_HEALTHCHECK_RUN_INVALID")
			}
		}
		return nil
	}
	for _, provider := range c.Providers {
		if err := provider.Initial(); err != nil {
			return err
		}
	}
	return nil
}
