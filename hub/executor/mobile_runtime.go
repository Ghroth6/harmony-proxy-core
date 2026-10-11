package executor

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/tunnel"
)

// PublishMobileFixed transfers only the static proxy/rule candidate. No listener,
// DNS, TUN, provider initialization, profile, updater, or resource path is entered.
// Runtime owns RetireConfig after success; the caller retains Discard on error.
func PublishMobileFixed(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || cfg.General == nil {
		return errors.New("mobile candidate missing")
	}
	disabled, err := sniffer.NewDispatcher(&sniffer.Config{Enable: false})
	if err != nil {
		return errors.New("mobile sniffer configuration")
	}
	mux.Lock()
	defer mux.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.CheckCandidate(); err != nil {
		return err
	}
	if err := retireConfigLocked(ctx, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.TransferToRuntime(); err != nil {
		return err
	}
	appliedCandidate = cfg
	tunnel.OnSuspend()
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	tunnel.UpdateSniffer(disabled)
	tunnel.SetMode(tunnel.Rule)
	tunnel.SetFindProcessMode(process.FindProcessOff)
	resolver.DisableIPv6 = true
	resolver.ProxyServerHostResolver = resolver.SystemResolver
	dialer.SetTcpConcurrent(false)
	dialer.DefaultInterface.Store("")
	dialer.DefaultRoutingMark.Store(0)
	dialer.DefaultInterfaceFinder.Store(nil)
	retiringConfig = nil
	return nil
}

// Activation is separate from publication and verifies the exact transferred
// candidate. The mobile run calls this only after its actual entry is ready.
func ActivateMobileFixed(cfg *config.Config) error {
	mux.Lock()
	defer mux.Unlock()
	if cfg == nil || appliedCandidate != cfg {
		return errors.New("mobile candidate inactive")
	}
	tunnel.OnRunning()
	return nil
}

// PublishMobilePolicy publishes the already verified original-policy objects.
// Platform listeners, TUN, first acquisition and updaters remain separate.
// Runtime must choose this entry explicitly; fixed-node publication retains its
// older IPv4/TCP settings and never silently substitutes for original policy.
func PublishMobilePolicy(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || cfg.General == nil {
		return errors.New("mobile original candidate missing")
	}
	if _, ok := cfg.MobilePolicyContext(); !ok {
		return errors.New("mobile original candidate identity missing")
	}
	disabled, err := sniffer.NewDispatcher(&sniffer.Config{Enable: false})
	if err != nil {
		return errors.New("mobile sniffer configuration")
	}
	mux.Lock()
	defer mux.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.CheckCandidate(); err != nil {
		return err
	}
	if err := retireConfigLocked(ctx, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.TransferToRuntime(); err != nil {
		return err
	}
	appliedCandidate = cfg
	tunnel.OnSuspend()
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateHosts(cfg.Hosts)
	tunnel.UpdateSniffer(disabled)
	tunnel.SetMode(cfg.General.Mode)
	tunnel.SetFindProcessMode(cfg.General.FindProcessMode)
	// Internal management requests inherit the actual run context. This installs
	// no listener and grants no admission while forwarding is still suspended.
	initInnerTcp()
	resolver.DisableIPv6 = !cfg.General.IPv6
	resolver.ProxyServerHostResolver, resolver.DirectHostResolver = cfg.MobileNodeResolvers()
	if r, mapper, enabled := cfg.MobileDNSResolvers(); enabled {
		resolver.DefaultResolver, resolver.DefaultHostMapper, resolver.DefaultService = r, mapper, cfg.MobileDNSService()
		resolver.UseSystemHosts = cfg.DNS.UseSystemHosts
		if r.ProxyResolver.Invalid() {
			resolver.ProxyServerHostResolver = r.ProxyResolver
		} else {
			resolver.ProxyServerHostResolver = r.Resolver
		}
		if r.DirectResolver.Invalid() {
			resolver.DirectHostResolver = r.DirectResolver
		} else {
			resolver.DirectHostResolver = r.Resolver
		}
	}
	dialer.SetTcpConcurrent(cfg.General.TCPConcurrent)
	// Raw device-interface/routing marks cannot take ownership from the actual
	// mobile snapshot and socket-protection gate.
	dialer.DefaultInterface.Store("")
	dialer.DefaultRoutingMark.Store(0)
	dialer.DefaultInterfaceFinder.Store(nil)
	retiringConfig = nil
	return nil
}

func ActivateMobilePolicy(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("mobile original candidate inactive")
	}
	if _, ok := cfg.MobilePolicyContext(); !ok {
		return errors.New("mobile original candidate inactive")
	}
	return ActivateMobileFixed(cfg)
}
