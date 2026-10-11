package config

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter"
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
	physical   C.Dialer
}

func (d *mobileCandidateDialer) context(ctx context.Context) (context.Context, error) {
	if generation := d.generation.Load(); generation != 0 {
		return protection.WithGeneration(ctx, generation), nil
	}
	d.attempts.Add(1)
	return nil, errPreparationNetwork
}
func (d *mobileCandidateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, err := d.context(ctx)
	if err != nil {
		return nil, err
	}
	return d.physical.DialContext(ctx, network, address)
}
func (d *mobileCandidateDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	ctx, err := d.context(ctx)
	if err != nil {
		return nil, err
	}
	return d.physical.ListenPacket(ctx, network, address, remote)
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

// BuildMobileSelectedCandidate independently gates every original node field,
// constructs fresh owned adapters and keeps all network paths fenced until
// runtime activation. It never initializes providers or installs global DNS.
func BuildMobileSelectedCandidate(raw *RawConfig) (cfg *Config, err error) {
	owned := &configresources.Set{}
	gate := &mobileCandidateDialer{physical: dialer.NewDialer(dialer.WithOnlySingleStack(true), dialer.WithResolver(resolver.SystemResolver))}
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
	if err = MobileNodeFields(raw.Proxy[0]); err != nil {
		return cfg, err
	}
	cfg.Proxies, cfg.Providers, err = parseProxiesInto(raw, owned, adapter.WithDialerForAPI(gate))
	if err != nil {
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
