package config

import (
	"context"
	"errors"
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

// MobileSelectedShape is the explicit local selected-node policy. It does not
// claim coverage of a source YAML's groups, DNS, providers or original rules.
func MobileSelectedShape(raw *RawConfig) bool { return mobileFixedShape(raw) }

// MobileLegacySelectedShape preserves the older label only for its audited
// original fields. New TLS/transport/domain/UDP settings use the v2 label.
func MobileLegacySelectedShape(raw *RawConfig) bool {
	if !mobileFixedShape(raw) {
		return false
	}
	n := raw.Proxy[0]
	server, ok := n["server"].(string)
	if !ok {
		return true
	} // Existing scalar diagnostics remain authoritative.
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
	return true
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

// BuildMobileSelectedCandidate constructs fresh upstream adapters for the
// explicit selected-node shape and keeps all network paths fenced until
// runtime activation. It never initializes providers or installs global DNS.
func BuildMobileSelectedCandidate(raw *RawConfig) (cfg *Config, err error) {
	owned := &configresources.Set{}
	gate := &mobileCandidateDialer{options: []dialer.Option{dialer.WithOnlySingleStack(true), dialer.WithResolver(resolver.SystemResolver)}}
	cfg = &Config{candidateResources: owned, mobileNetwork: gate, General: &General{Mode: tunnel.Rule, FindProcessMode: process.FindProcessOff, IPv6: false}, Providers: map[string]P.ProxyProvider{}, RuleProviders: map[string]P.RuleProvider{}, SubRules: map[string][]C.Rule{}}
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
	cfg.Proxies, cfg.Providers, err = parseProxiesInto(raw, owned, adapter.WithPhysicalDialerForAPI(gate.newPhysical), adapter.WithProxyLookupForAPI(lookup), adapter.WithTunnelForAPI(nil), adapter.WithResourcePolicyForAPI(mobileResourcePolicy), adapter.WithAdapterWrapper(func(a outbound.ProxyAdapter) outbound.ProxyAdapter {
		return &mobilePolicyBuiltin{ProxyAdapter: a, fence: gate}
	}))
	if err != nil {
		if errors.Is(err, adapter.ErrUnsupportedProxyType) {
			return cfg, &MobileValidationError{Code: "PROXY_TYPE_UNSUPPORTED", cause: err}
		}
		var gap *outbound.APIIntegrationError
		if errors.As(err, &gap) {
			return cfg, &MobileValidationError{Code: gap.Code, cause: err}
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
