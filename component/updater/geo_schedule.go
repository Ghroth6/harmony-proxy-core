package updater

import (
	"context"
	"github.com/metacubex/mihomo/log"
	"time"
)

// RunGeoUpdater is the official stale-first, then interval schedule with an
// embedding-owned context and update target. It returns after cancellation.
func RunGeoUpdater(ctx context.Context, interval time.Duration, lastUpdate time.Time, update func(context.Context) error) {
	if interval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %s", interval)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if lastUpdate.Add(interval).Before(time.Now()) {
		if err := update(ctx); err != nil {
			log.Errorln("[GEO] Failed to update GEO database: %s", err)
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := update(ctx); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err)
			}
		}
	}
}
