package config

import (
	"context"
	"errors"
	"sync"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	RC "github.com/metacubex/mihomo/rules/common"
)

func parseDNSDomainGeo(country, target string, parsers ...RC.ParseRuleFunc) (C.DomainMatcher, error) {
	if len(parsers) == 0 {
		return RC.NewGEOSITE(country, target)
	}
	rule, err := parsers[0]("GEOSITE", country, target, nil, nil)
	if err != nil {
		return nil, err
	}
	matcher, ok := rule.(C.DomainMatcher)
	if !ok {
		return nil, errors.New("POLICY_DNS_INVALID")
	}
	return matcher, nil
}
func parseDNSIPGeo(country, target string, noResolve bool, parsers ...RC.ParseRuleFunc) (*RC.GEOIP, error) {
	if len(parsers) == 0 {
		return RC.NewGEOIP(country, target, false, noResolve)
	}
	var params []string
	if noResolve {
		params = []string{"no-resolve"}
	}
	rule, err := parsers[0]("GEOIP", country, target, params, nil)
	if err != nil {
		return nil, err
	}
	matcher, ok := rule.(*RC.GEOIP)
	if !ok {
		return nil, errors.New("POLICY_DNS_INVALID")
	}
	return matcher, nil
}

type mobileDNS struct {
	mu        sync.Mutex
	activated bool
	owner     *dns.ResolverOwner
	resolvers dns.Resolvers
	mapper    *dns.ResolverEnhancer
	service   *dns.Service
}

func buildMobileDNS(cfg *DNS, generalIPv6 bool) *mobileDNS {
	owner := dns.NewResolverOwner()
	ipv6 := cfg.IPv6 && generalIPv6
	r := dns.NewResolver(dns.Config{Owner: owner, Main: cfg.NameServer, Fallback: cfg.Fallback, Default: cfg.DefaultNameserver, ProxyServer: cfg.ProxyServerNameserver, DirectServer: cfg.DirectNameServer, DirectFollowPolicy: cfg.DirectFollowPolicy, IPv6: ipv6, IPv6Timeout: cfg.IPv6Timeout, FallbackIPFilter: cfg.FallbackIPFilter, FallbackDomainFilter: cfg.FallbackDomainFilter, FallbackLazyQuery: cfg.FallbackLazyQuery, Policy: cfg.NameServerPolicy, ProxyServerPolicy: cfg.ProxyServerPolicy, CacheAlgorithm: cfg.CacheAlgorithm, CacheMaxSize: cfg.CacheMaxSize})
	m := dns.NewEnhancer(dns.EnhancerConfig{IPv6: ipv6, EnhancedMode: cfg.EnhancedMode, FakeIPPool: cfg.FakeIPPool, FakeIPPool6: cfg.FakeIPPool6, FakeIPSkipper: cfg.FakeIPSkipper, FakeIPTTL: cfg.FakeIPTTL, UseHosts: cfg.UseHosts})
	return &mobileDNS{owner: owner, resolvers: r, mapper: m, service: dns.NewService(r, m)}
}

// Client DNS can remain disabled while domain nodes still need bootstrap DNS.
// Give that system policy its own inactive owner/cache, never the global
// SystemResolver's shared work. Nameservers are read from the real snapshot at
// query time, after explicit activation; construction performs no lookup.
func buildMobileSystemBootstrap(ipv6 bool) *mobileDNS {
	owner := dns.NewResolverOwner()
	r := dns.NewResolver(dns.Config{Owner: owner, Main: []dns.NameServer{{Net: "system"}}, IPv6: ipv6})
	return &mobileDNS{owner: owner, resolvers: r}
}

func (c *Config) MobileNodeResolvers() (proxy, direct resolver.Resolver) {
	if c == nil || c.mobileDNS == nil {
		return nil, nil
	}
	r := c.mobileDNS.resolvers
	proxy, direct = r.Resolver, r.Resolver
	if r.ProxyResolver.Invalid() {
		proxy = r.ProxyResolver
	}
	if r.DirectResolver.Invalid() {
		direct = r.DirectResolver
	}
	return
}

func (c *Config) MobileDNSService() *dns.Service {
	if c == nil || c.mobileDNS == nil || c.mobileDNS.service == nil {
		return nil
	}
	return c.mobileDNS.service
}

func (c *Config) mobileAdapterDNSService() resolver.Service {
	if service := c.MobileDNSService(); service != nil {
		return service
	}
	return nil
}
func (c *Config) MobileDNSResolvers() (dns.Resolvers, *dns.ResolverEnhancer, bool) {
	if c == nil || c.mobileDNS == nil || c.mobileDNS.service == nil {
		return dns.Resolvers{}, nil, false
	}
	return c.mobileDNS.resolvers, c.mobileDNS.mapper, true
}

// Bind DNS before client ingress. Publication alone keeps this instance closed.
func (c *Config) ActivateMobilePolicyDNS(root context.Context) error {
	if c == nil || c.mobilePolicy == nil || c.mobileNetwork == nil {
		return &MobileValidationError{Code: "POLICY_IDENTITY_INVALID"}
	}
	if err := c.CheckCandidate(); err != nil {
		return err
	}
	if c.mobileAdapterResources != nil {
		if err := c.mobileAdapterResources.Activate(); err != nil {
			return err
		}
	}
	if c.mobileDNS == nil {
		return nil
	}
	c.mobileDNS.mu.Lock()
	defer c.mobileDNS.mu.Unlock()
	if c.mobileDNS.activated {
		return nil
	}
	if c.mobilePolicyResources != nil && c.mobilePolicyResources.FakeIPState != nil {
		if err := c.mobilePolicyResources.FakeIPState.Activate(); err != nil {
			return err
		}
	}
	scope, err := forwarding.Context(c.mobileNetwork.generation.Load())
	if err != nil {
		return err
	}
	if err = c.mobileDNS.owner.Activate(forwarding.Bind(root, scope)); err != nil {
		return err
	}
	c.mobileDNS.activated = true
	return nil
}
