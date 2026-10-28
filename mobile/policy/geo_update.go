package policy

import (
	"context"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/updater"
	P "github.com/metacubex/mihomo/constant/provider"
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
		resource := fixed[requirement.RefID]
		vehicle := &preparedVehicle{resource: resource.value, uri: requirement.SourceURI, kind: P.HTTP, session: s, requirement: requirement,
			decode: func(data []byte) ([]string, error) { return nil, geodata.VerifyPrepared(requirement.Kind, data) }}
		last := time.Now()
		if info, err := s.engine.root.Stat(resource.value.RelativePath); err == nil {
			last = info.ModTime()
		}
		s.geoUpdates = append(s.geoUpdates, geoRefresh{vehicle, time.Duration(requirement.IntervalSeconds) * time.Second, last})
	}
}
func (s *resourceSession) startGeoUpdates(ctx context.Context) error {
	for _, update := range s.geoUpdates {
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
