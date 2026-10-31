package policy

import (
	"context"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"time"
)

type geoRefresh struct {
	vehicle    *preparedVehicle
	interval   time.Duration
	lastUpdate time.Time
}

func (s *resourceSession) prepareGeoUpdates(requirements []contract.Requirement, fixed map[string]fixedResource) {
	for _, requirement := range requirements {
		if requirement.Kind == "rule-provider" || requirement.IntervalSeconds <= 0 {
			continue
		}
		fixedResource := fixed[requirement.RefID]
		base := resource.NewHTTPVehicle(requirement.SourceURI, "", "DIRECT", nil, resource.DefaultHttpTimeout, requirement.MaxBytes)
		vehicle := newPreparedVehicle(base, "", fixedResource.value, requirement, s)
		last := time.Now()
		if info, err := s.engine.root.Stat(fixedResource.value.RelativePath); err == nil {
			last = info.ModTime()
		}
		s.geoUpdates = append(s.geoUpdates, geoRefresh{vehicle, time.Duration(requirement.IntervalSeconds) * time.Second, last})
	}
}
func (s *resourceSession) startGeoUpdates(ctx context.Context) error {
	for _, update := range s.geoUpdates {
		update := update
		root, finish, err := s.AcquireWorker(ctx)
		if err != nil {
			return err
		}
		go func() {
			defer finish()
			updater.RunGeoUpdater(root, update.interval, update.lastUpdate, func(ctx context.Context) (err error) {
				v := update.vehicle
				defer func() { v.PreparedUpdateResult(false, err) }()
				data, _, err := v.Read(ctx, utils.HashType{})
				if err != nil {
					return err
				}
				if err = geodata.VerifyPrepared(v.resource.Kind, data); err != nil {
					return err
				}
				if err = v.PrepareUpdate(ctx, data); err != nil {
					return err
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.retired || ctx.Err() != nil {
					return context.Canceled
				}
				return s.geo.Replace(v.resource.Kind, data)
			})
		}()
	}
	return nil
}
