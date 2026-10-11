package provider

import (
	"context"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

// NewPreparedRuleSetProvider keeps the original vehicle/interval but replaces
// eager Initial with fixed bytes. decode must validate every line before an
// upstream strategy is allowed to insert any part of the payload.
func NewPreparedRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle, input []byte, parse common.ParseRuleFunc, decode func([]byte) ([]string, error)) (*RuleSetProvider, error) {
	rp := &RuleSetProvider{&ruleSetProvider{baseProvider: baseProvider{behavior: behavior}, format: format, notifyDone: make(chan struct{})}}
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, nil, func(bytes []byte) (ruleStrategy, error) {
		payload, err := decode(bytes)
		if err != nil {
			return nil, err
		}
		return rulesParseInline(payload, newStrategy(behavior, parse)), nil
	}, func(strategy ruleStrategy) {
		rp.strategyMu.Lock()
		rp.strategy = strategy
		rp.strategyMu.Unlock()
	})
	runtime.SetFinalizer(rp, (*RuleSetProvider).Close)
	if _, err := rp.Fetcher.InitialPrepared(input); err != nil {
		return rp, err
	}
	return rp, nil
}

func (rp *RuleSetProvider) ActivateScheduled(ctx context.Context) error {
	return rp.Fetcher.ActivateScheduled(ctx)
}
