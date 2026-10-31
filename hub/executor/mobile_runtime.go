package executor

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// PublishMobilePolicy publishes the already verified prepared-policy objects.
// Platform listeners, TUN, first acquisition and updaters remain separate.
// Runtime owns RetireConfig after success; the caller retains Discard on error.
func PublishMobilePolicy(ctx context.Context, cfg *config.Config) error {
	if cfg == nil || cfg.General == nil {
		return errors.New("mobile original candidate missing")
	}
	if _, ok := cfg.MobilePolicyContext(); !ok {
		return errors.New("mobile original candidate identity missing")
	}
	if err := cfg.BindMobilePolicyHealthChecks(ctx); err != nil {
		return err
	}
	dispatcher, err := sniffer.NewDispatcher(cfg.Sniffer)
	if err != nil {
		return errors.New("POLICY_SNIFFER_INVALID")
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
	log.SetLevel(cfg.General.LogLevel)
	updateOutboundSettings(cfg.General)
	if cfg.Experimental != nil {
		updateExperimental(cfg.Experimental)
	}
	if cfg.TLS != nil {
		ca.ResetCertificate()
		for _, certificate := range cfg.TLS.CustomTrustCert {
			if err := ca.AddCertificate(certificate); err != nil {
				log.Warnln("%s\nadd error: %s", certificate, err)
			}
		}
	}
	tunnel.OnSuspend()
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateHosts(cfg.Hosts)
	tunnel.UpdateSniffer(dispatcher)
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
	mux.Lock()
	if appliedCandidate != cfg {
		mux.Unlock()
		return errors.New("mobile original candidate inactive")
	}
	tunnel.OnRunning()
	mux.Unlock()
	return cfg.ActivateMobilePolicyHealthChecks()
}
