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
