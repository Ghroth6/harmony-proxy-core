package config

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/configresources"
	TLSPolicy "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
)

var errPreparationNetwork = errors.New("preparation network is forbidden")

type preparationDialer struct {
	attempts atomic.Int32
	observer func()
}

func (d *preparationDialer) denied() error {
	d.attempts.Add(1)
	if d.observer != nil {
		d.observer()
	}
	return errPreparationNetwork
}
func (d *preparationDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.denied()
}
func (d *preparationDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, d.denied()
}

var _ C.Dialer = (*preparationDialer)(nil)

// ValidateMobileNode constructs and fully discards a node through real engine
// adapters. All constructor network requests are denied at the C.Dialer system
// boundary. The optional observer reports attempts, never destinations or data.
func ValidateMobileNode(node map[string]any, networkObserver func()) (err error) {
	if err = MobileNodeFields(node); err != nil {
		return
	}
	owned := &configresources.Set{}
	guard := &preparationDialer{observer: networkObserver}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "CORE_FAILURE"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := owned.Close(ctx); closeErr != nil {
			err = &MobileValidationError{Code: "CANDIDATE_CLEANUP_FAILED", cause: closeErr}
		}
		if guard.attempts.Load() != 0 {
			err = &MobileValidationError{Code: "PREPARATION_NETWORK_FORBIDDEN", cause: err}
		}
	}()
	proxy, parseErr := adapter.ParseProxy(node, adapter.WithDialerForAPI(guard))
	if proxy != nil {
		owned.AddProxy(proxy)
	}
	if parseErr != nil {
		return &MobileValidationError{Code: "PROXY_INVALID", cause: parseErr}
	}
	return nil
}

// MobileNodeFields independently gates every original field before any weakly
// typed engine decoder can drop fields or substitute fallback transport values.
func MobileNodeFields(node map[string]any) error {
	invalid := func() error { return &MobileValidationError{Code: "PROXY_INVALID"} }
	unsupported := func() error { return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"} }
	typeName, _ := node["type"].(string)
	allowed := "name type server port password udp"
	switch typeName {
	case "ss":
		allowed += " cipher"
	case "anytls":
		allowed += " sni alpn client-fingerprint skip-cert-verify fingerprint"
	case "trojan":
		allowed += " sni alpn client-fingerprint skip-cert-verify fingerprint tls network ws-opts grpc-opts"
	case "vless":
		allowed = "name type server port udp uuid flow encryption tls alpn client-fingerprint skip-cert-verify fingerprint servername reality-opts ech-opts mobile-uri-opts network ws-opts packet-encoding grpc-opts h2-opts http-opts xhttp-opts"
	case "vmess":
		allowed = "name type server port udp uuid alterId cipher tls alpn client-fingerprint skip-cert-verify fingerprint servername network ws-opts packet-encoding grpc-opts h2-opts http-opts"
	case "hysteria2":
		allowed += " sni alpn skip-cert-verify fingerprint obfs obfs-password ports"
	default:
		return unsupported()
	}
	for key := range node {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return unsupported()
		}
	}
	required := []string{"name", "server"}
	if typeName == "vless" || typeName == "vmess" {
		required = append(required, "uuid")
	} else {
		required = append(required, "password")
	}
	for _, field := range required {
		value, ok := node[field].(string)
		if !ok || value == "" {
			return invalid()
		}
	}
	server := node["server"].(string)
	if address, err := netip.ParseAddr(server); err == nil {
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return unsupported()
		}
	} else if !mobileTLSName(server) {
		return invalid()
	}
	port, ok := node["port"].(int)
	if !ok || port < 1 || port > 65535 {
		return invalid()
	}
	for _, key := range []string{"udp", "skip-cert-verify", "tls"} {
		if value, present := node[key]; present {
			if _, ok := value.(bool); !ok {
				return invalid()
			}
		}
	}
	if typeName == "ss" {
		if node["cipher"] != "aes-128-gcm" && node["cipher"] != "chacha20-ietf-poly1305" {
			return unsupported()
		}
		return nil
	}
	if typeName == "trojan" || typeName == "vless" || typeName == "vmess" {
		if typeName == "trojan" {
			if tls, present := node["tls"]; present && tls != true {
				return unsupported()
			}
		}
		if err := mobileTransportFields(node); err != nil {
			return err
		}
	}
	if typeName == "vmess" {
		if aid, ok := node["alterId"].(int); !ok || aid < 0 || aid > 65535 {
			return invalid()
		}
		switch node["cipher"] {
		case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
		default:
			return unsupported()
		}
	}
	if typeName == "hysteria2" {
		if value, present := node["ports"]; present {
			ports, ok := value.(string)
			if !ok || !mobilePortRanges(ports) {
				return invalid()
			}
		}
		if value, present := node["udp"]; present && value != true {
			return unsupported()
		}
		if obfs, present := node["obfs"]; present {
			if obfs != "salamander" {
				return unsupported()
			}
			if password, ok := node["obfs-password"].(string); !ok || password == "" {
				return invalid()
			}
		} else if _, present := node["obfs-password"]; present {
			return unsupported()
		}
	}
	if typeName == "vless" {
		if value, present := node["mobile-uri-opts"]; present {
			opts, ok := value.(map[string]any)
			if !ok || len(opts) != 1 {
				return invalid()
			}
			for key, value := range opts {
				if key != "quicSecurity" || value != "" && value != "none" {
					return unsupported()
				}
			}
		}
		if value, present := node["flow"]; present && value != "" && (value != "xtls-rprx-vision" || node["tls"] != true) {
			return unsupported()
		}
		if value, present := node["encryption"]; present && value != "" && value != "none" {
			return unsupported()
		}
		if value, present := node["packet-encoding"]; present && value != "packetaddr" && value != "xudp" {
			return unsupported()
		}
		if value, present := node["reality-opts"]; present {
			opts, ok := value.(map[string]any)
			if !ok || node["tls"] != true {
				return invalid()
			}
			for key := range opts {
				if key != "public-key" && key != "short-id" {
					return unsupported()
				}
			}
			public, ok := opts["public-key"].(string)
			if !ok || public == "" {
				return invalid()
			}
			short := ""
			if value, present := opts["short-id"]; present {
				var ok bool
				short, ok = value.(string)
				if !ok {
					return invalid()
				}
			}
			if _, err := (outbound.RealityOptions{PublicKey: public, ShortID: short}).Parse(); err != nil {
				return invalid()
			}
		}
		if value, present := node["ech-opts"]; present {
			opts, ok := value.(map[string]any)
			if !ok {
				return invalid()
			}
			var options outbound.ECHOptions
			for key, value := range opts {
				switch key {
				case "enable":
					var ok bool
					options.Enable, ok = value.(bool)
					if !ok {
						return invalid()
					}
				case "config", "query-server-name":
					text, ok := value.(string)
					if !ok || strings.ContainsAny(text, "\x00\r\n") {
						return invalid()
					}
					if key == "config" {
						options.Config = text
					} else {
						if text != "" && !mobileTLSName(text) {
							return invalid()
						}
						options.QueryServerName = text
					}
				default:
					return unsupported()
				}
			}
			if _, err := options.Parse(); err != nil {
				return invalid()
			}
		}
	}
	sni := server
	sniField := "sni"
	if typeName == "vless" || typeName == "vmess" {
		sniField = "servername"
	}
	if value, present := node[sniField]; present {
		text, ok := value.(string)
		if !ok || !mobileNodeTLSName(text) {
			return invalid()
		}
		if text != "" {
			sni = text
		}
	}
	fingerprint := ""
	if value, present := node["client-fingerprint"]; present {
		text, ok := value.(string)
		if !ok {
			return invalid()
		}
		if !TLSPolicy.SupportsFingerprint(text) {
			return unsupported()
		}
	}
	if value, present := node["fingerprint"]; present {
		text, ok := value.(string)
		if !ok {
			return invalid()
		}
		fingerprint = text
	}
	var alpn []string
	if value, present := node["alpn"]; present {
		switch list := value.(type) {
		case []string:
			alpn = list
		case []any:
			for _, item := range list {
				text, ok := item.(string)
				if !ok {
					return invalid()
				}
				alpn = append(alpn, text)
			}
		default:
			return invalid()
		}
		if len(alpn) == 0 || len(alpn) > 16 {
			return invalid()
		}
		for _, item := range alpn {
			if item == "" || len(item) > 255 || strings.ContainsAny(item, "\x00\r\n") {
				return invalid()
			}
		}
	}
	_, err := (&vmess.TLSConfig{Host: sni, FingerPrint: fingerprint, NextProtos: alpn}).ToStdConfig()
	if err != nil {
		return invalid()
	}
	return nil
}

// The upstream generic uint16 range parser can wrap oversized values and
// reorder descending ranges. Validate the original spelling before using it.
func mobilePortRanges(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return false
		}
		var previous uint64
		for _, bound := range bounds {
			for _, r := range bound {
				if r < '0' || r > '9' {
					return false
				}
			}
			port, err := strconv.ParseUint(bound, 10, 16)
			if err != nil || port == 0 || previous > port {
				return false
			}
			previous = port
		}
	}
	return true
}

// Empty names use the adapter's original server fallback. IP literals are
// certificate verification names even though TLS does not send them as SNI.
// The older fixed-node contract continues to use mobileTLSName independently.
func mobileNodeTLSName(value string) bool {
	if value == "" {
		return true
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
	}
	return mobileTLSName(value)
}

func mobileTransportFields(node map[string]any) error {
	invalid := func() error { return &MobileValidationError{Code: "PROXY_INVALID"} }
	unsupported := func() error { return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"} }
	network := "tcp"
	if value, present := node["network"]; present {
		var ok bool
		network, ok = value.(string)
		if !ok {
			return invalid()
		}
	}
	if network != "tcp" && network != "ws" && network != "grpc" && network != "h2" && network != "http" && network != "xhttp" {
		return unsupported()
	}
	if node["type"] == "trojan" && network != "tcp" && network != "ws" && network != "grpc" {
		return unsupported()
	}
	for _, binding := range []struct{ key, network, fields string }{
		{"grpc-opts", "grpc", "grpc-service-name"}, {"h2-opts", "h2", "host path"}, {"http-opts", "http", "method path headers"}, {"xhttp-opts", "xhttp", "host path mode headers"},
	} {
		if value, present := node[binding.key]; present {
			if network != binding.network && !(network == "tcp" && binding.key == "http-opts") {
				return unsupported()
			}
			opts, ok := value.(map[string]any)
			if !ok {
				return invalid()
			}
			for key, value := range opts {
				if !strings.Contains(" "+binding.fields+" ", " "+key+" ") {
					return unsupported()
				}
				switch key {
				case "host", "path":
					if (binding.key == "h2-opts" && key == "host") || (binding.key == "http-opts" && key == "path") {
						if !mobileStringList(value) {
							return invalid()
						}
					} else {
						if text, ok := value.(string); !ok || strings.ContainsAny(text, "\x00\r\n") {
							return invalid()
						}
					}
				case "mode":
					switch value {
					case "auto", "packet-up", "stream-up", "stream-one":
					default:
						return unsupported()
					}
				case "headers":
					headers, ok := value.(map[string]any)
					if !ok {
						return invalid()
					}
					for name, value := range headers {
						if name == "" || strings.ContainsAny(name, "\x00\r\n") {
							return invalid()
						}
						if binding.key == "http-opts" {
							if !mobileStringList(value) {
								return invalid()
							}
						} else if text, ok := value.(string); !ok || strings.ContainsAny(text, "\x00\r\n") {
							return invalid()
						}
					}
				default:
					if text, ok := value.(string); !ok || strings.ContainsAny(text, "\x00\r\n") {
						return invalid()
					}
				}
			}
		}
	}
	if value, present := node["ws-opts"]; present {
		if network != "ws" {
			return unsupported()
		}
		opts, ok := value.(map[string]any)
		if !ok {
			return invalid()
		}
		for key, value := range opts {
			switch key {
			case "path":
				if path, ok := value.(string); !ok || strings.ContainsAny(path, "\x00\r\n") {
					return invalid()
				}
			case "headers":
				headers, ok := value.(map[string]any)
				if !ok {
					return invalid()
				}
				for name, value := range headers {
					text, ok := value.(string)
					if !ok || name == "" || strings.ContainsAny(name+text, "\x00\r\n") {
						return invalid()
					}
				}
			default:
				return unsupported()
			}
		}
	}
	return nil
}

func mobileStringList(value any) bool {
	var items []string
	switch v := value.(type) {
	case []string:
		items = v
	case []any:
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return false
			}
			items = append(items, text)
		}
	default:
		return false
	}
	if len(items) == 0 || len(items) > 64 {
		return false
	}
	for _, item := range items {
		if item == "" || strings.ContainsAny(item, "\x00\r\n") {
			return false
		}
	}
	return true
}
