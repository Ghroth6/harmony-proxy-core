package adapter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/lifecycle"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

var ErrUnsupportedProxyType = errors.New("unsupported proxy type")

func ParseProxy(mapping map[string]any, options ...ProxyOption) (_ C.Proxy, retErr error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	opt := applyProxyOptions(options...)
	var resources *lifecycle.Group
	var release func()
	if opt.ResourceOwner != nil {
		resources = &lifecycle.Group{}
		var err error
		release, err = opt.ResourceOwner.Adopt(resources, opt.DeferResourceActivation)
		if err != nil {
			return nil, err
		}
		defer func() {
			if retErr != nil {
				retErr = errors.Join(retErr, resources.Close())
				release()
			}
		}()
	}
	basicOption := outbound.BasicOption{
		DialerForAPI:         opt.DialerForAPI,
		PhysicalDialerForAPI: opt.PhysicalDialerForAPI,
		ProxyLookupForAPI:    opt.ProxyLookupForAPI,
		ResourcePolicyForAPI: opt.ResourcePolicyForAPI,
		ResourceOwner:        resources,
		DNSServiceForAPI:     opt.DNSServiceForAPI,
		TunnelForAPI:         opt.TunnelForAPI,
		ProviderName:         opt.ProviderName,
	}

	var (
		proxy outbound.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	case "hysteria":
		hyOption := &outbound.HysteriaOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria(*hyOption)
	case "hysteria2":
		hyOption := &outbound.Hysteria2Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria2(*hyOption)
	case "wireguard":
		wgOption := &outbound.WireGuardOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, wgOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewWireGuard(*wgOption)
	case "tuic":
		tuicOption := &outbound.TuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTuic(*tuicOption)
	case "shadowquic":
		shadowQuicOption := &outbound.ShadowQuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, shadowQuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowQuic(*shadowQuicOption)
	case "gost-relay":
		relayOption := &outbound.GostRelayOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, relayOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewGostRelay(*relayOption)
	case "direct":
		directOption := &outbound.DirectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, directOption)
		if err != nil {
			break
		}
		proxy = outbound.NewDirectWithOption(*directOption)
	case "dns":
		dnsOptions := &outbound.DnsOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, dnsOptions)
		if err != nil {
			break
		}
		proxy = outbound.NewDnsWithOption(*dnsOptions)
	case "reject":
		rejectOption := &outbound.RejectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rejectOption)
		if err != nil {
			break
		}
		proxy = outbound.NewRejectWithOption(*rejectOption)
	case "rematch":
		rematchOption := &outbound.RematchOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rematchOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewRematch(*rematchOption)
	case "ssh":
		sshOption := &outbound.SshOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sshOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSsh(*sshOption)
	case "mieru":
		mieruOption := &outbound.MieruOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, mieruOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMieru(*mieruOption)
	case "anytls":
		anytlsOption := &outbound.AnyTLSOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, anytlsOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewAnyTLS(*anytlsOption)
	case "sudoku":
		sudokuOption := &outbound.SudokuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sudokuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSudoku(*sudokuOption)
	case "masque":
		masqueOption := &outbound.MasqueOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, masqueOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMasque(*masqueOption)
	case "trusttunnel":
		trustTunnelOption := &outbound.TrustTunnelOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trustTunnelOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrustTunnel(*trustTunnelOption)
	case "openvpn":
		openVPNOption := &outbound.OpenVPNOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, openVPNOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewOpenVPN(*openVPNOption)
	case "tailscale":
		tailscaleOption := &outbound.TailscaleOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tailscaleOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTailscale(*tailscaleOption)
	case "zerotier":
		zeroTierOption := &outbound.ZeroTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, zeroTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewZeroTier(*zeroTierOption)
	case "easytier":
		easyTierOption := &outbound.EasyTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, easyTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewEasyTier(*easyTierOption)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProxyType, proxyType)
	}

	if err != nil {
		return nil, err
	}
	// A constructor error may leave a typed nil in proxy. Only successful
	// construction transfers ownership here; later wrapping failures must release
	// that adapter without relying on a finalizer that has not been installed yet.
	defer func() {
		if retErr != nil {
			var candidate configresources.Set
			candidate.AddAdapter(proxy)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			retErr = errors.Join(retErr, candidate.Close(ctx))
		}
	}()

	if muxMapping, muxExist := mapping["smux"].(map[string]any); muxExist {
		muxOption := &outbound.SingMuxOption{}
		err = decoder.Decode(muxMapping, muxOption)
		if err != nil {
			return nil, err
		}
		if muxOption.Enabled {
			wrapped, err := outbound.NewSingMux(*muxOption, proxy)
			if err != nil {
				return nil, err
			}
			proxy = wrapped
		}
	}

	if resources != nil {
		proxy = &resourceOwnedAdapter{ProxyAdapter: proxy, resources: resources, release: release}
	}
	if opt.WrapAdapter != nil {
		proxy = opt.WrapAdapter(proxy)
	}
	proxy = outbound.NewAutoCloseProxyAdapter(proxy)
	return NewProxy(proxy), nil
}

type proxyOption struct {
	DeferResourceActivation bool
	DialerForAPI            C.Dialer
	TunnelForAPI            C.Tunnel
	ProviderName            string
	PhysicalDialerForAPI    func([]dialer.Option) C.Dialer
	ProxyLookupForAPI       proxydialer.ProxyLookup
	ResourceOwner           *lifecycle.Group
	ResourcePolicyForAPI    func(string) error
	DNSServiceForAPI        func() resolver.Service
	WrapAdapter             func(outbound.ProxyAdapter) outbound.ProxyAdapter
}

func WithDeferredResourceActivation() ProxyOption {
	return func(opt *proxyOption) { opt.DeferResourceActivation = true }
}

func applyProxyOptions(options ...ProxyOption) proxyOption {
	opt := proxyOption{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}

type ProxyOption func(opt *proxyOption)

func WithDialerForAPI(dialer C.Dialer) ProxyOption {
	return func(opt *proxyOption) {
		opt.DialerForAPI = dialer
	}
}

// WithPhysicalDialerForAPI composes a physical transport without replacing the
// original dialer-proxy chain or the adapter's interface/IP/TFO/MPTCP options.
func WithPhysicalDialerForAPI(factory func([]dialer.Option) C.Dialer) ProxyOption {
	return func(opt *proxyOption) { opt.PhysicalDialerForAPI = factory }
}

func WithProxyLookupForAPI(lookup proxydialer.ProxyLookup) ProxyOption {
	return func(opt *proxyOption) { opt.ProxyLookupForAPI = lookup }
}

func WithResourcePolicyForAPI(policy func(string) error) ProxyOption {
	return func(opt *proxyOption) { opt.ResourcePolicyForAPI = policy }
}

func WithDNSServiceForAPI(service func() resolver.Service) ProxyOption {
	return func(opt *proxyOption) { opt.DNSServiceForAPI = service }
}

// WithAdapterWrapper binds embedded API ownership before a parsed adapter is
// exposed or leased. The wrapper must retain the adapter's Close obligation.
func WithAdapterWrapper(wrap func(outbound.ProxyAdapter) outbound.ProxyAdapter) ProxyOption {
	return func(opt *proxyOption) { opt.WrapAdapter = wrap }
}

func WithTunnelForAPI(tunnel C.Tunnel) ProxyOption {
	return func(opt *proxyOption) {
		opt.TunnelForAPI = tunnel
	}
}

func WithProviderName(name string) ProxyOption {
	return func(opt *proxyOption) {
		opt.ProviderName = name
	}
}

func WithResourceOwner(owner *lifecycle.Group) ProxyOption {
	return func(opt *proxyOption) { opt.ResourceOwner = owner }
}
