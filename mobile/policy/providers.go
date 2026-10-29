package policy

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"go.yaml.in/yaml/v3"
)

func (e *Engine) prepareProviders(raw *config.RawConfig, prepared contract.PreparedContext, requirements []contract.Requirement, fixed map[string]fixedResource) (*config.MobilePolicyResources, error) {
	inputs := &config.MobilePolicyResources{RuleProviders: map[string]P.RuleProvider{}, ResourceAttempt: func() { actualResourceAttempts.Add(1) }}
	geo, parseGeo, err := prepareGeoData(raw, fixed)
	if err != nil {
		return inputs, err
	}
	session, err := newResourceSession(e, prepared, inputs.RuleProviders)
	if err != nil {
		e.retainClose(geo, geo.Close())
		return inputs, err
	}
	session.geo = geo
	session.prepareGeoUpdates(requirements, fixed)
	inputs.Services = session
	if raw.Profile.StoreFakeIP && raw.DNS.Enable && raw.DNS.EnhancedMode == C.DNSFakeIP {
		inputs.FakeIPState, err = fakeip.NewScopedPersistence(e.root, prepared.InputDigest)
		if err != nil {
			return inputs, err
		}
		session.fakeIPState = inputs.FakeIPState
	}
	inputs.ParseRule = rules.ScopedParser(inputs.RuleProviders, parseGeo)
	names := make([]string, 0, len(raw.RuleProvider))
	for name := range raw.RuleProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		mapping := raw.RuleProvider[name]
		behaviorName, _ := mapping["behavior"].(string)
		formatName, _ := mapping["format"].(string)
		if formatName == "" {
			formatName = "yaml"
		}
		behavior, _ := P.ParseBehavior(behaviorName)
		format, _ := P.ParseRuleFormat(formatName)
		decode := func(input []byte) ([]string, error) {
			return RP.RuleSetPayload(input, behavior, format, inputs.ParseRule)
		}
		if mapping["type"] == "inline" {
			data, err := yaml.Marshal(map[string]any{"payload": mapping["payload"]})
			if err != nil {
				return inputs, errors.New("POLICY_RESOURCE_PAYLOAD_INVALID")
			}
			payload, err := decode(data)
			if err != nil {
				return inputs, err
			}
			inputs.RuleProviders[name] = RP.NewInlineProvider(name, behavior, payload, inputs.ParseRule)
			continue
		}
		ref := digest([]byte(prepared.InputDigest + ":resource:rule-provider:" + name))
		resource, present := fixed[ref]
		if !present {
			return inputs, errors.New("POLICY_RESOURCES_MISSING")
		}
		interval, _ := mapping["interval"].(int)
		uri, _ := mapping["url"].(string)
		proxy, _ := mapping["proxy"].(string)
		var requirement contract.Requirement
		for _, item := range requirements {
			if item.RefID == ref {
				requirement = item
			}
		}
		vehicle := &preparedVehicle{resource: resource.value, uri: uri, proxy: proxy, kind: P.HTTP, session: session, requirement: requirement, decode: decode}
		if mapping["type"] == "file" {
			vehicle.kind = P.File
		}
		provider, err := RP.NewPreparedRuleSetProvider(name, behavior, format, time.Duration(interval)*time.Second, vehicle, resource.bytes, inputs.ParseRule)
		if provider != nil {
			inputs.RuleProviders[name] = provider
		}
		if err != nil {
			return inputs, err
		}
	}
	return inputs, nil
}

func discardPreparedProviders(inputs *config.MobilePolicyResources) error {
	if inputs == nil {
		return nil
	}
	var errs []error
	if inputs.Services != nil {
		inputs.Services.Cancel()
		errs = append(errs, inputs.Services.Wait(context.Background()))
	}
	for _, provider := range inputs.RuleProviders {
		if owner, ok := provider.(interface {
			Cancel()
			Wait(context.Context) error
		}); ok {
			owner.Cancel()
			errs = append(errs, owner.Wait(context.Background()))
		}
	}
	return errors.Join(errs...)
}

var _ C.Rule = (*RP.RuleSet)(nil)
