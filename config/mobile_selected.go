package config

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/lifecycle"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/protection"
	"github.com/metacubex/mihomo/tunnel"
)

// MobileSelectedShape identifies the independent manual static-check subset.
// Runtime preparation accepts composed node policies through mobile/policy.
func MobileSelectedShape(raw *RawConfig) bool {
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

// MobileLegacySelectedShape preserves the older label only for its audited
// original fields. New TLS/transport/domain/UDP settings use the v2 label.
func MobileLegacySelectedShape(raw *RawConfig) bool {
	if !MobileSelectedShape(raw) {
		return false
	}
	n := raw.Proxy[0]
	server, ok := n["server"].(string)
	if !ok {
		return false
	}
	address, err := netip.ParseAddr(server)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || n["udp"] == true {
		return false
	}
	allowed := "name type server port password udp"
	switch n["type"] {
	case "ss":
		allowed += " cipher"
	case "trojan":
		allowed += " sni network skip-cert-verify"
		if value, ok := n["network"].(string); ok && value != "tcp" {
			return false
		}
	default:
		return false
	}
	for key := range n {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return false
		}
	}
	return validateLegacyMobileScope(raw) == nil
}

type mobileCandidateDialer struct {
	generation atomic.Uint64
	attempts   atomic.Int32
	options    []dialer.Option
}

type mobilePhysicalDialer struct {
	fence   *mobileCandidateDialer
	options []dialer.Option
}

func (d *mobileCandidateDialer) newPhysical(options []dialer.Option) C.Dialer {
	return &mobilePhysicalDialer{fence: d, options: append([]dialer.Option(nil), options...)}
}
func (d *mobilePhysicalDialer) current(ctx context.Context) (context.Context, C.Dialer, error) {
	ctx, err := d.fence.context(ctx)
	if err != nil {
		return nil, nil, err
	}
	options := append(append([]dialer.Option(nil), d.fence.options...), d.options...)
	return ctx, dialer.NewDialer(options...), nil
}
func (d *mobilePhysicalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, physical, err := d.current(ctx)
	if err != nil {
		return nil, err
	}
	return physical.DialContext(ctx, network, address)
}
func (d *mobilePhysicalDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	ctx, physical, err := d.current(ctx)
	if err != nil {
		return nil, err
	}
	return physical.ListenPacket(ctx, network, address, remote)
}

func (d *mobileCandidateDialer) context(ctx context.Context) (context.Context, error) {
	if generation := d.generation.Load(); generation != 0 {
		return protection.WithGeneration(ctx, generation), nil
	}
	d.attempts.Add(1)
	return nil, errPreparationNetwork
}

// ActivateMobileNetwork is the explicit runtime-only transition after a real
// protection gate and matching online snapshot have been accepted. Preparation
// and saved candidates never invoke it. Retirement disables it again.
func (c *Config) ActivateMobileNetwork(generation uint64) error {
	if c == nil || generation == 0 || c.CheckCandidate() != nil {
		return &MobileValidationError{Code: "CANDIDATE_INVALID"}
	}
	if c.mobileNetwork != nil {
		c.mobileNetwork.generation.Store(generation)
	}
	return nil
}

// BuildMobileSelectedCandidate serves the independent manual static validator.
// Runtime candidates are built only by the prepared-policy owner. This static
// candidate never initializes providers, installs DNS or activates networking.
func BuildMobileSelectedCandidate(raw *RawConfig) (cfg *Config, err error) {
	owned := &configresources.Set{}
	gate := &mobileCandidateDialer{options: []dialer.Option{dialer.WithOnlySingleStack(true), dialer.WithResolver(resolver.SystemResolver)}}
	cfg = &Config{candidateResources: owned, mobileAdapterResources: &lifecycle.Group{}, mobileNetwork: gate, General: &General{Mode: tunnel.Rule, FindProcessMode: process.FindProcessOff, IPv6: false}, Providers: map[string]P.ProxyProvider{}, RuleProviders: map[string]P.RuleProvider{}, SubRules: map[string][]C.Rule{}}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "CORE_FAILURE"}
		}
		if gate.attempts.Load() != 0 {
			err = &MobileValidationError{Code: "PREPARATION_NETWORK_FORBIDDEN"}
		}
	}()
	if !MobileSelectedShape(raw) {
		return cfg, &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"}
	}
	lookup := &mobilePolicyProxyLookup{candidate: cfg}
	cfg.Proxies, cfg.Providers, err = parseProxiesInto(raw, owned, adapter.WithPhysicalDialerForAPI(gate.newPhysical), adapter.WithProxyLookupForAPI(lookup), adapter.WithTunnelForAPI(nil), adapter.WithResourceOwner(cfg.mobileAdapterResources), adapter.WithDNSServiceForAPI(cfg.mobileAdapterDNSService), adapter.WithAdapterWrapper(func(a outbound.ProxyAdapter) outbound.ProxyAdapter {
		return &mobilePolicyBuiltin{ProxyAdapter: a, fence: gate}
	}))
	if err != nil {
		if errors.Is(err, adapter.ErrUnsupportedProxyType) {
			return cfg, &MobileValidationError{Code: "PROXY_TYPE_UNSUPPORTED", cause: err}
		}
		return cfg, &MobileValidationError{Code: "PROXY_OR_GROUP_INVALID", cause: err}
	}
	cfg.Rules, err = parseRules(raw.Rule, cfg.Proxies, nil, nil, "rules")
	if err != nil {
		return cfg, &MobileValidationError{Code: "RULE_INVALID", cause: err}
	}
	return cfg, nil
}

func ValidateMobileSelected(raw *RawConfig) (err error) {
	if !MobileSelectedShape(raw) {
		return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"}
	}
	candidate, err := BuildMobileSelectedCandidate(raw)
	if candidate != nil {
		if cleanup := candidate.Discard(context.Background()); cleanup != nil {
			return &MobileValidationError{Code: "CANDIDATE_CLEANUP_FAILED", cause: cleanup}
		}
	}
	return err
}
