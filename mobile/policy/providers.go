package policy

import (
	"context"
	"errors"
	"path/filepath"
	"sort"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RB "github.com/metacubex/mihomo/rules/bundle"
	RP "github.com/metacubex/mihomo/rules/provider"
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
		ref := digest([]byte(prepared.InputDigest + ":resource:rule-provider:" + name))
		var requirement contract.Requirement
		var vehicleErr error
		for _, item := range requirements {
			if item.RefID == ref {
				requirement = item
			}
		}
		provider, err := RP.ParseRuleProvider(name, raw.RuleProvider[name], inputs.ParseRule,
			func(path string) resource.BundleFile { return RB.MakeBundleFileIn(e.root.Name(), path) },
			func(base P.Vehicle) P.Vehicle {
				// The process home is fixed to this private root in production. Resolve
				// the same relative path against the engine root for independent callers.
				relative, pathErr := filepath.Rel(C.Path.HomeDir(), base.Path())
				if pathErr != nil || !filepath.IsLocal(relative) {
					vehicleErr = errors.New("POLICY_RESOURCE_PATH_INVALID")
					return base
				}
				privatePath := filepath.Join(e.root.Name(), relative)
				if base.Type() == P.File {
					base = resource.NewFileVehicle(privatePath)
				}
				value := contract.Resource{RefID: ref, Kind: requirement.Kind, Format: requirement.Format, SourceDigest: requirement.SourceDigest}
				if saved, ok := fixed[ref]; ok {
					value = saved.value
				}
				return newPreparedVehicle(base, privatePath, value, requirement, session)
			})
		if provider != nil {
			inputs.RuleProviders[name] = provider
		}
		if err != nil {
			return inputs, err
		}
		if vehicleErr != nil {
			return inputs, vehicleErr
		}
		if saved, ok := fixed[ref]; ok {
			stat, err := e.root.Stat(saved.value.RelativePath)
			if err != nil {
				return inputs, err
			}
			if err := RP.PrepareRuleSetProvider(provider, saved.bytes, stat.ModTime()); err != nil {
				return inputs, err
			}
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
