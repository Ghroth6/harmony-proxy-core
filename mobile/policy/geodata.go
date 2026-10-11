package policy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
)

func prepareGeoData(raw *config.RawConfig, fixed map[string]fixedResource) (*geodata.Prepared, RC.ParseRuleFunc, error) {
	data := map[string][]byte{}
	for _, resource := range fixed {
		if resource.value.Kind != "rule-provider" {
			data[resource.value.Kind] = resource.bytes
		}
	}
	owner, err := geodata.NewPrepared(data, raw.GeodataLoader, raw.GeositeMatcher)
	if err != nil {
		return nil, nil, errors.New("POLICY_RESOURCE_PAYLOAD_INVALID")
	}
	parse := func(tp, payload, target string, params []string, sub map[string][]C.Rule) (C.Rule, error) {
		isSrc, noResolve := RC.ParseParams(params)
		switch tp {
		case "GEOSITE":
			return RC.NewPreparedGEOSITE(payload, target, func() (router.DomainMatcher, error) { return owner.Site(payload) })
		case "GEOIP", "SRC-GEOIP":
			isSrc = isSrc || tp == "SRC-GEOIP"
			country := strings.ToLower(payload)
			if country == "lan" {
				return RC.NewGEOIP(country, target, isSrc, noResolve)
			}
			if raw.GeodataMode {
				getter := func() (router.IPMatcher, error) { return owner.IP(payload) }
				if _, err := getter(); err != nil {
					return nil, errors.New("POLICY_RESOURCE_PAYLOAD_INVALID")
				}
				match := func(ip netip.Addr) bool { matcher, err := getter(); return err == nil && matcher.Match(ip) }
				return RC.NewPreparedGEOIP(country, target, isSrc, noResolve, match, getter), nil
			}
			if data["mmdb"] == nil {
				return nil, errors.New("POLICY_RESOURCES_MISSING")
			}
			return RC.NewPreparedGEOIP(country, target, isSrc, noResolve, func(ip netip.Addr) bool { return slices.Contains(owner.LookupCode(ip), country) }, nil), nil
		case "IP-ASN", "SRC-IP-ASN":
			if data["asn"] == nil {
				return nil, errors.New("POLICY_RESOURCES_MISSING")
			}
			return RC.NewPreparedIPASN(payload, target, isSrc || tp == "SRC-IP-ASN", noResolve, owner.LookupASN), nil
		default:
			return nil, errors.New("POLICY_RULE_INVALID")
		}
	}
	return owner, parse, nil
}
