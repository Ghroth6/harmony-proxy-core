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
// eager Initial with fixed bytes. Formats and invalid entries use rulesParse,
// exactly as the ordinary provider does.
func NewPreparedRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle, input []byte, parse common.ParseRuleFunc) (*RuleSetProvider, error) {
	rp := &RuleSetProvider{&ruleSetProvider{baseProvider: baseProvider{behavior: behavior}, format: format, notifyDone: make(chan struct{})}}
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, nil, func(bytes []byte) (ruleStrategy, error) {
		return rulesParse(bytes, newStrategy(behavior, parse), format)
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

// RuleSetPayload uses the upstream format decoder and strategy, retaining the
// accepted text entries for dependency discovery before a candidate is active.
// MRS is validated directly and has no classical text dependencies.
func RuleSetPayload(input []byte, behavior P.RuleBehavior, format P.RuleFormat, parse common.ParseRuleFunc) ([]string, error) {
	strategy := newStrategy(behavior, parse)
	if format == P.MrsRule {
		_, err := rulesParse(input, strategy, format)
		return nil, err
	}
	collector := &payloadCollector{ruleStrategy: strategy}
	_, err := rulesParse(input, collector, format)
	return collector.payload, err
}

type payloadCollector struct {
	ruleStrategy
	payload []string
}

func (c *payloadCollector) Insert(rule string) {
	before := c.Count()
	c.ruleStrategy.Insert(rule)
	if c.Count() > before {
		c.payload = append(c.payload, rule)
	}
}

func (rp *RuleSetProvider) ActivateScheduled(ctx context.Context) error {
	return rp.Fetcher.ActivateScheduled(ctx)
}
