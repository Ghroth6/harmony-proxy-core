package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{pid: int32(os.Getpid())}

	go DefaultManager.handle()
}

type Manager struct {
	connections xsync.Map[string, Tracker]
	// One lock gives each accounting event, bucket rollover and reset a single
	// boundary across both all-traffic and proxy-only counters.
	trafficMu sync.Mutex
	all       trafficCounters
	proxy     trafficCounters
	pid       int32
	memory    atomic.Uint64
}

type trafficPair struct{ up, down int64 }

type trafficCounters struct {
	pending, previous, total trafficPair
}

func (c *trafficCounters) add(up, down int64) {
	c.pending.up += up
	c.pending.down += down
	c.total.up += up
	c.total.down += down
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(size int64) {
	m.recordTraffic(size, 0, false)
}

func (m *Manager) PushDownloaded(size int64) {
	m.recordTraffic(0, size, false)
}

// recordTraffic counts one tracker accounting event. Unclassified public Push
// calls remain part of all traffic; only trackers with a known proxy egress add
// to the proxy subset. Negative sizes cannot subtract previously counted bytes.
func (m *Manager) recordTraffic(up, down int64, proxy bool) {
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	if up == 0 && down == 0 {
		return
	}
	m.trafficMu.Lock()
	m.all.add(up, down)
	if proxy {
		m.proxy.add(up, down)
	}
	m.trafficMu.Unlock()
}

func (m *Manager) Now() (up int64, down int64) {
	return m.NowTraffic(false)
}

func (m *Manager) Total() (up, down int64) {
	return m.TotalTraffic(false)
}

// NowTraffic returns byte counts from the previous one-second bucket. Reading
// does not consume the bucket; it is not an instantaneous or normalized rate.
func (m *Manager) NowTraffic(onlyProxy bool) (up, down int64) {
	m.trafficMu.Lock()
	defer m.trafficMu.Unlock()
	if onlyProxy {
		return m.proxy.previous.up, m.proxy.previous.down
	}
	return m.all.previous.up, m.all.previous.down
}

// TotalTraffic includes closed connections since initialization or the last
// ResetStatistic. Internal trackers with pushToManager=false are excluded.
func (m *Manager) TotalTraffic(onlyProxy bool) (up, down int64) {
	m.trafficMu.Lock()
	defer m.trafficMu.Unlock()
	if onlyProxy {
		return m.proxy.total.up, m.proxy.total.down
	}
	return m.all.total.up, m.all.total.down
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory.Load()
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	up, down := m.Total()
	return &Snapshot{
		UploadTotal:   up,
		DownloadTotal: down,
		Connections:   connections,
		Memory:        m.memory.Load(),
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory.Store(stat.RSS)
}

func (m *Manager) ResetStatistic() {
	// In-flight I/O is assigned by when it is accounted, not when it started.
	// Connection-local totals and activity are intentionally not reset.
	m.trafficMu.Lock()
	m.all = trafficCounters{}
	m.proxy = trafficCounters{}
	m.trafficMu.Unlock()
}

func (m *Manager) rolloverTraffic() {
	m.trafficMu.Lock()
	m.all.previous, m.all.pending = m.all.pending, trafficPair{}
	m.proxy.previous, m.proxy.pending = m.proxy.pending, trafficPair{}
	m.trafficMu.Unlock()
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		m.rolloverTraffic()
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
