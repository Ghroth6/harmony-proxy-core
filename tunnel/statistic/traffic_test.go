package statistic

import (
	"io"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

type trafficConn struct {
	activityConn
	kind C.AdapterType
	name string
}

func (c *trafficConn) EgressType() C.AdapterType { return c.kind }
func (c *trafficConn) Chains() C.Chain           { return C.Chain{c.name, "selected-group"} }

type trafficPacketConn struct {
	activityPacketConn
	kind C.AdapterType
	name string
}

func (c *trafficPacketConn) EgressType() C.AdapterType { return c.kind }
func (c *trafficPacketConn) Chains() C.Chain           { return C.Chain{c.name, "selected-group"} }

func assertTraffic(t *testing.T, m *Manager, onlyProxy bool, wantUp, wantDown int64) {
	t.Helper()
	if up, down := m.TotalTraffic(onlyProxy); up != wantUp || down != wantDown {
		t.Fatalf("TotalTraffic(%v) = %d/%d, want %d/%d", onlyProxy, up, down, wantUp, wantDown)
	}
}

func TestTrafficClassifiesEstablishedTypeNotNames(t *testing.T) {
	for _, tc := range []struct {
		kind  C.AdapterType
		name  string
		proxy bool
	}{
		{C.Direct, "my-direct", false}, {C.Compatible, "COMPATIBLE", false},
		{C.Dns, "local-dns", false}, {C.Reject, "REJECT", false},
		{C.RejectDrop, "DROP", false}, {C.Pass, "PASS", false},
		{C.PassRule, "PASS-RULE", false}, {C.Rematch, "REMATCH", false},
		{C.Selector, "group", false}, {C.Fallback, "group", false},
		{C.LoadBalance, "group", false}, {C.URLTest, "group", false},
		{C.Relay, "legacy-group", false}, {C.AdapterType(-1), "unknown", false},
		{C.AdapterType(999), "future", false}, {C.Socks5, "DIRECT", true},
		{C.Shadowsocks, "COMPATIBLE", true}, {C.Http, "my-direct", true},
	} {
		t.Run(tc.kind.String()+"/"+tc.name, func(t *testing.T) {
			m := &Manager{}
			tcp := NewTCPTracker(&trafficConn{kind: tc.kind, name: tc.name}, m, &C.Metadata{}, nil, 3, 5, true)
			udp := NewUDPTracker(&trafficPacketConn{kind: tc.kind, name: tc.name}, m, &C.Metadata{}, nil, 7, 11, true)
			assertTraffic(t, m, false, 10, 16)
			if tc.proxy {
				assertTraffic(t, m, true, 10, 16)
			} else {
				assertTraffic(t, m, true, 0, 0)
			}
			_ = tcp.Close()
			_ = udp.Close()
			if len(m.Snapshot().Connections) != 0 {
				t.Fatal("closed connections remain registered")
			}
			assertTraffic(t, m, false, 10, 16)
		})
	}
}

func TestEveryKnownProxyProtocolCountsAsProxy(t *testing.T) {
	// Keep an explicit list so additions to the adapter enum require a decision.
	for _, kind := range []C.AdapterType{
		C.Shadowsocks, C.ShadowsocksR, C.Snell, C.Socks5, C.Http,
		C.Vmess, C.Vless, C.Trojan, C.Hysteria, C.Hysteria2, C.WireGuard,
		C.Tuic, C.Ssh, C.Mieru, C.AnyTLS, C.Sudoku, C.Masque,
		C.TrustTunnel, C.ShadowQuic, C.OpenVPN, C.Tailscale, C.ZeroTier,
		C.EasyTier, C.GostRelay,
	} {
		m := &Manager{}
		NewTCPTracker(&trafficConn{kind: kind}, m, &C.Metadata{}, nil, 1, 2, true)
		assertTraffic(t, m, true, 1, 2)
	}
}

func TestTrafficCountsTCPPathsAndExcludesInternalTrackers(t *testing.T) {
	for _, push := range []bool{true, false} {
		m := &Manager{}
		conn := &trafficConn{kind: C.Socks5, name: "DIRECT", activityConn: activityConn{n: 3, err: io.ErrUnexpectedEOF}}
		conn.bufferRead = func(b *buf.Buffer) error { b.Truncate(5); return nil }
		conn.bufferWrite = func(b *buf.Buffer) error { b.Release(); return nil }
		tracker := NewTCPTracker(conn, m, &C.Metadata{}, nil, 2, 4, push)
		// The tracked socket's classification does not follow later selections.
		conn.kind = C.Direct
		_, _ = tracker.Read(make([]byte, 8))
		_, _ = tracker.Write(make([]byte, 8))
		readBuffer := buf.NewSize(8)
		_ = tracker.ReadBuffer(readBuffer)
		readBuffer.Release()
		writeBuffer := buf.NewSize(7)
		writeBuffer.Truncate(7)
		_ = tracker.WriteBuffer(writeBuffer)
		_, reads := tracker.UnwrapReader()
		_, writes := tracker.UnwrapWriter()
		reads[0](11)
		writes[0](13)
		_ = tracker.Close()
		if tracker.UploadTotal.Load() != 25 || tracker.DownloadTotal.Load() != 23 {
			t.Fatal("connection counters must include each accounting path exactly once")
		}
		if push {
			assertTraffic(t, m, false, 25, 23)
			assertTraffic(t, m, true, 25, 23)
		} else {
			assertTraffic(t, m, false, 0, 0)
			assertTraffic(t, m, true, 0, 0)
		}
	}
}

func TestTrafficCountsUDPPathsAndExcludesInternalTrackers(t *testing.T) {
	for _, push := range []bool{true, false} {
		m := &Manager{}
		conn := &trafficPacketConn{kind: C.Trojan, activityPacketConn: activityPacketConn{n: 3, err: io.ErrUnexpectedEOF}}
		tracker := NewUDPTracker(conn, m, &C.Metadata{}, nil, 2, 4, push)
		_, _, _ = tracker.ReadFrom(make([]byte, 8))
		_, _, _, _ = tracker.WaitReadFrom()
		_, _ = tracker.WriteTo(make([]byte, 8), nil)
		_ = tracker.Close()
		if tracker.UploadTotal.Load() != 5 || tracker.DownloadTotal.Load() != 10 {
			t.Fatal("UDP accounting changed")
		}
		if push {
			assertTraffic(t, m, false, 5, 10)
			assertTraffic(t, m, true, 5, 10)
		} else {
			assertTraffic(t, m, false, 0, 0)
			assertTraffic(t, m, true, 0, 0)
		}
	}
}

func TestTrafficBucketsAreNonConsumingAndSeparateFromTotals(t *testing.T) {
	m := &Manager{}
	NewTCPTracker(&trafficConn{kind: C.Socks5}, m, &C.Metadata{}, nil, 3, 5, true)
	NewUDPTracker(&trafficPacketConn{kind: C.Direct}, m, &C.Metadata{}, nil, 7, 11, true)
	if up, down := m.NowTraffic(false); up != 0 || down != 0 {
		t.Fatal("unfinished bucket was exposed")
	}
	m.rolloverTraffic()
	for i := 0; i < 3; i++ {
		if up, down := m.NowTraffic(false); up != 10 || down != 16 {
			t.Fatal("reading all traffic consumed the bucket")
		}
		if up, down := m.NowTraffic(true); up != 3 || down != 5 {
			t.Fatal("reading proxy traffic consumed or contaminated the bucket")
		}
	}
	m.rolloverTraffic()
	if up, down := m.Now(); up != 0 || down != 0 {
		t.Fatal("empty interval must replace the previous bucket")
	}
	assertTraffic(t, m, false, 10, 16)
	assertTraffic(t, m, true, 3, 5)
}

func TestTrafficResetKeepsLiveConnectionsAndTheirOwnTotals(t *testing.T) {
	m := &Manager{}
	tracker := NewTCPTracker(&trafficConn{kind: C.Socks5, activityConn: activityConn{n: 7}}, m, &C.Metadata{}, nil, 3, 5, true)
	m.rolloverTraffic()
	m.ResetStatistic()
	for _, proxy := range []bool{false, true} {
		assertTraffic(t, m, proxy, 0, 0)
		if up, down := m.NowTraffic(proxy); up != 0 || down != 0 {
			t.Fatal("reset did not clear previous bucket")
		}
	}
	if m.Get(tracker.ID()) != tracker || tracker.UploadTotal.Load() != 3 || tracker.DownloadTotal.Load() != 5 {
		t.Fatal("manager reset changed live connection accounting")
	}
	_, _ = tracker.Write(nil)
	m.rolloverTraffic()
	assertTraffic(t, m, true, 7, 0)
	if up, down := m.NowTraffic(true); up != 7 || down != 0 {
		t.Fatal("old pending bytes survived reset")
	}
}

func TestTrafficConcurrentAccountingAndRollover(t *testing.T) {
	m := &Manager{}
	tracker := NewTCPTracker(&trafficConn{kind: C.Socks5, activityConn: activityConn{n: 1}}, m, &C.Metadata{}, nil, 0, 0, true)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				_, _ = tracker.Read(nil)
				_, _ = tracker.Write(nil)
				if j%100 == 0 {
					m.rolloverTraffic()
					m.NowTraffic(true)
					m.Snapshot()
				}
			}
		}()
	}
	workers.Wait()
	_ = tracker.Close()
	assertTraffic(t, m, false, 8000, 8000)
	assertTraffic(t, m, true, 8000, 8000)
}

func TestConcurrentResetHasOneBoundaryForTrafficPairs(t *testing.T) {
	m := &Manager{}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				m.recordTraffic(1, 2, true)
				if j%7 == 0 {
					m.ResetStatistic()
				}
				m.rolloverTraffic()
				for _, proxy := range []bool{false, true} {
					if up, down := m.TotalTraffic(proxy); down != up*2 {
						t.Error("reset split an accounting event")
					}
					if up, down := m.NowTraffic(proxy); down != up*2 {
						t.Error("rollover split an accounting event")
					}
				}
			}
		}()
	}
	workers.Wait()
	// A reset after all writers is complete clears all classes and buckets.
	m.ResetStatistic()
	m.recordTraffic(3, 6, true)
	m.PushUploaded(5) // unknown origin remains all-traffic only
	m.PushDownloaded(-1)
	m.rolloverTraffic()
	assertTraffic(t, m, false, 8, 6)
	assertTraffic(t, m, true, 3, 6)
}
