//go:build with_gvisor

package runtime

import (
	"sort"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"
)

const maxConnectionObservations = 16

type connectionSample struct {
	record   observation
	activity time.Time
	payload  bool
}

// All helpers run under the owning Transfer mutex. Get never calls back into a
// Transfer; Manager.Join emits only after its registry Store has returned.
// Keep accounting values, never a connection or forwarding lease owner.
func sampleConnection(record observation) connectionSample {
	record.value.Upload = record.info.UploadTotal.Load()
	record.value.Download = record.info.DownloadTotal.Load()
	return connectionSample{record: record, activity: record.info.LastActivity(), payload: record.value.Upload > 0 || record.value.Download > 0}
}

func newerConnection(a, b connectionSample) bool {
	if !a.activity.Equal(b.activity) {
		return a.activity.After(b.activity)
	}
	return a.record.value.Sequence > b.record.value.Sequence
}

func (e *runEngine) retainClosedObservation(record observation) {
	e.observations = append(e.observations, record)
	if len(e.observations) <= maxConnectionObservations {
		return
	}
	samples := make([]connectionSample, 0, len(e.observations))
	for _, record := range e.observations {
		samples = append(samples, sampleConnection(record))
	}
	sort.Slice(samples, func(i, j int) bool { return newerConnection(samples[i], samples[j]) })
	e.observations = make([]observation, 0, maxConnectionObservations)
	for _, sample := range samples[:maxConnectionObservations] {
		e.observations = append(e.observations, sample.record)
	}
}

func (e *runEngine) retireClosedObservations() {
	for id, record := range e.activeObservations {
		current := statistic.DefaultManager.Get(id)
		if current != nil && current.Info() == record.info {
			continue
		}
		delete(e.activeObservations, id)
		e.retainClosedObservation(record)
	}
}

// Reserve half the existing window for active payload-bearing connections and
// half for recent ended/initial records; unused slots backfill by real activity.
// Snapshot timestamps before sorting so concurrent I/O cannot reorder a sort.
func (e *runEngine) selectedObservations() []observation {
	e.retireClosedObservations()
	active, recent := []connectionSample{}, []connectionSample{}
	for _, record := range e.activeObservations {
		sample := sampleConnection(record)
		if sample.payload {
			active = append(active, sample)
		} else {
			recent = append(recent, sample)
		}
	}
	for _, record := range e.observations {
		recent = append(recent, sampleConnection(record))
	}
	sort.Slice(active, func(i, j int) bool { return newerConnection(active[i], active[j]) })
	sort.Slice(recent, func(i, j int) bool { return newerConnection(recent[i], recent[j]) })
	take := func(values []connectionSample) int {
		if len(values) > maxConnectionObservations/2 {
			return maxConnectionObservations / 2
		}
		return len(values)
	}
	a, r := take(active), take(recent)
	selected := append(append([]connectionSample{}, active[:a]...), recent[:r]...)
	remaining := append(append([]connectionSample{}, active[a:]...), recent[r:]...)
	sort.Slice(remaining, func(i, j int) bool { return newerConnection(remaining[i], remaining[j]) })
	for _, sample := range remaining {
		if len(selected) == maxConnectionObservations {
			break
		}
		selected = append(selected, sample)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].record.value.Sequence < selected[j].record.value.Sequence })
	result := make([]observation, 0, len(selected))
	for _, sample := range selected {
		result = append(result, sample.record)
	}
	return result
}
