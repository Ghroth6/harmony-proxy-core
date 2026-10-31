package provider

import (
	"context"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

// PrepareRuleSetProvider supplies immutable initial bytes to the ordinary
// provider. Its fallback, vehicle, parser and runtime scheduling stay upstream.
func PrepareRuleSetProvider(provider P.RuleProvider, input []byte, modified time.Time) error {
	rp := provider.(*RuleSetProvider)
	strategy, err := rp.Fetcher.InitialPrepared(input, modified)
	if err != nil {
		return err
	}
	rp.strategyMu.Lock()
	rp.strategy = strategy
	rp.strategyMu.Unlock()
	return nil
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
