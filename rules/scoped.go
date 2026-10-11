package rules

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
)

// ScopedParser reuses ordinary rule implementations while freezing resource
// references to this candidate. Recursive logic also uses the same parser.
func ScopedParser(providers map[string]P.RuleProvider, geo RC.ParseRuleFunc) RC.ParseRuleFunc {
	var parse RC.ParseRuleFunc
	parse = func(tp, payload, target string, params []string, sub map[string][]C.Rule) (C.Rule, error) {
		switch tp {
		case "AND":
			return logic.NewAND(payload, target, parse)
		case "OR":
			return logic.NewOR(payload, target, parse)
		case "NOT":
			return logic.NewNOT(payload, target, parse)
		case "SUB-RULE":
			return logic.NewSubRule(payload, target, sub, parse)
		case "RULE-SET":
			provider := providers[payload]
			if provider == nil {
				return nil, errors.New("candidate rule provider missing")
			}
			isSrc, noResolve := RC.ParseParams(params)
			return RP.NewBoundRuleSet(payload, target, isSrc, noResolve, provider)
		case "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN":
			if geo == nil {
				return nil, errors.New("candidate geodata missing")
			}
			return geo(tp, payload, target, params, sub)
		default:
			return ParseRule(tp, payload, target, params, sub)
		}
	}
	return parse
}
