package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/configresources"
)

// MobileValidationError exposes only a stable code and field, never raw parser
// text: native engine errors may contain configuration credentials.
type MobileValidationError struct {
	Code  string
	Field string
	cause error
}

// Existing parsers preserve their normal error text while identifying a safe
// stage/path for the mobile receipt. No error text is sent across the ABI.
type semanticParseError struct {
	code, field string
	cause       error
}

func (e *semanticParseError) Error() string { return e.cause.Error() }
func (e *semanticParseError) Unwrap() error { return e.cause }

func (e *MobileValidationError) Error() string { return e.Code }
func (e *MobileValidationError) Unwrap() error { return e.cause }

// ValidateMobileStatic invokes the engine's real proxy/group and rule semantics
// for the explicitly gated, self-contained subset. It never calls ParseRawConfig
// (which temporarily applies general globals), initializes providers, or applies
// a candidate. Every constructed object is discarded before returning.
func ValidateMobileStatic(raw *RawConfig) (err error) {
	// Defense in depth for direct callers: the mobile driver gates every original
	// YAML field, and this boundary independently rejects unsafe constructors.
	if len(raw.ProxyProvider) != 0 || len(raw.RuleProvider) != 0 || len(raw.SubRules) != 0 {
		return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"}
	}
	for index, proxy := range raw.Proxy {
		path := fmt.Sprintf("proxies[%d]", index)
		if proxy["type"] == "trojan" {
			if err := validateMobileTrojan(proxy, path); err != nil {
				return err
			}
			// Trojan is added only for the single fixed runtime sample, not
			// for the broader M1a static configuration family.
			if !mobileFixedShape(raw) {
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED"}
			}
			continue
		}
		// The normal runtime constructor permits some unusable endpoint values.
		// M1a's narrower static contract checks required scalar values and the
		// endpoint range here, in the core, before invoking that constructor.
		for _, field := range []string{"name", "type", "server", "cipher", "password"} {
			value, ok := proxy[field].(string)
			if !ok || (field != "password" && strings.TrimSpace(value) == "") {
				return &MobileValidationError{Code: "PROXY_INVALID", Field: path + "." + field}
			}
		}
		port, ok := proxy["port"].(int)
		if !ok || port < 1 || port > 65535 {
			return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".port"}
		}
		if value, present := proxy["udp"]; present {
			if _, ok := value.(bool); !ok {
				return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".udp"}
			}
		}
		if proxy["type"] != "ss" || (proxy["cipher"] != "aes-128-gcm" && proxy["cipher"] != "chacha20-ietf-poly1305") {
			return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxies"}
		}
		// This added cipher is audited only for the same fixed IPv4/TCP family
		// constructed at runtime; the older AES static scope stays unchanged.
		if proxy["cipher"] == "chacha20-ietf-poly1305" {
			if proxy["password"] == "" {
				return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".password"}
			}
			address, parseErr := netip.ParseAddr(proxy["server"].(string))
			if !mobileFixedShape(raw) || parseErr != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() ||
				(proxy["udp"] != nil && proxy["udp"] != false) {
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxies"}
			}
		}
		for field := range proxy {
			switch field {
			case "name", "type", "server", "port", "cipher", "password", "udp":
			default:
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxies"}
			}
		}
	}
	for _, group := range raw.ProxyGroup {
		if group["type"] != "select" {
			return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxy-groups"}
		}
		for field := range group {
			switch field {
			case "name", "type", "proxies":
			default:
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxy-groups"}
			}
		}
	}
	for _, rule := range raw.Rule {
		kind := strings.TrimSpace(strings.SplitN(rule, ",", 2)[0])
		if kind != "DOMAIN" && kind != "MATCH" {
			return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "rules"}
		}
	}
	owned := &configresources.Set{}
	defer func() {
		// This subset creates no external task. Still wait for every real Close;
		// a failed cleanup can never be reported as a semantic pass.
		if cleanupErr := owned.Close(context.Background()); cleanupErr != nil {
			err = &MobileValidationError{Code: "CANDIDATE_CLEANUP_FAILED", cause: errors.Join(err, cleanupErr)}
		} else if !errors.Is(owned.CheckTransfer(), configresources.ErrCleanupStarted) {
			// A usable/publishable candidate must never escape validation, even
			// when it currently happens to own adapters whose Close is a no-op.
			err = &MobileValidationError{Code: "CANDIDATE_CLEANUP_FAILED", cause: err}
		}
	}()
	proxies, _, parseErr := parseProxiesInto(raw, owned)
	if parseErr != nil {
		var detail *semanticParseError
		if errors.As(parseErr, &detail) {
			return &MobileValidationError{Code: detail.code, Field: detail.field, cause: parseErr}
		}
		return &MobileValidationError{Code: "PROXY_OR_GROUP_INVALID", cause: parseErr}
	}
	if _, parseErr = parseRules(raw.Rule, proxies, nil, nil, "rules"); parseErr != nil {
		var detail *semanticParseError
		if errors.As(parseErr, &detail) {
			return &MobileValidationError{Code: detail.code, Field: detail.field, cause: parseErr}
		}
		return &MobileValidationError{Code: "RULE_INVALID", Field: "rules", cause: parseErr}
	}
	return nil
}

func validateMobileTrojan(proxy map[string]any, path string) error {
	for _, field := range []string{"name", "type", "server", "password", "sni"} {
		value, ok := proxy[field].(string)
		if !ok || value == "" || (field != "password" && strings.TrimSpace(value) == "") {
			return &MobileValidationError{Code: "PROXY_INVALID", Field: path + "." + field}
		}
	}
	port, ok := proxy["port"].(int)
	if !ok || port < 1 || port > 65535 {
		return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".port"}
	}
	if !mobileTLSName(proxy["sni"].(string)) {
		return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".sni"}
	}
	address, err := netip.ParseAddr(proxy["server"].(string))
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: path + ".server"}
	}
	for key, value := range proxy {
		switch key {
		case "name", "type", "server", "port", "password", "sni":
		case "udp", "skip-cert-verify":
			if _, ok := value.(bool); !ok {
				return &MobileValidationError{Code: "PROXY_INVALID", Field: path + "." + key}
			}
			if key == "udp" && value != false {
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: path + "." + key}
			}
		case "network":
			if _, ok := value.(string); !ok {
				return &MobileValidationError{Code: "PROXY_INVALID", Field: path + ".network"}
			}
			if value != "tcp" {
				return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: path + ".network"}
			}
		default:
			return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxies"}
		}
	}
	return nil
}

// An explicit ASCII DNS hostname is mandatory. IP literals, wildcard names,
// empty labels, whitespace/control characters and implicit server fallback are
// outside this TLS SNI contract. This name never supplies the dial address.
func mobileTLSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}
