package config

import (
	"context"
	"errors"
	"fmt"
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
		if proxy["type"] != "ss" || proxy["cipher"] != "aes-128-gcm" {
			return &MobileValidationError{Code: "CAPABILITY_NOT_COVERED", Field: "proxies"}
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
