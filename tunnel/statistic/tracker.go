package statistic

import (
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

type Tracker interface {
	ID() string
	Close() error
	Info() *TrackerInfo
	LastActivity() time.Time
	C.Connection
}

type TrackerInfo struct {
	UUID          uuid.UUID    `json:"id"`
	Metadata      *C.Metadata  `json:"metadata"`
	UploadTotal   atomic.Int64 `json:"upload"`
	DownloadTotal atomic.Int64 `json:"download"`
	Start         time.Time    `json:"start"`
	Chain         C.Chain      `json:"chains"`
	ProviderChain C.Chain      `json:"providerChains"`
	Rule          string       `json:"rule"`
	RulePayload   string       `json:"rulePayload"`
	lastActivity  atomic.Int64
}

// LastActivity returns the creation time until payload I/O is confirmed, then
// the latest confirmed activity. Buffer operations and unwrapped copy callbacks
// cannot report every partial failed transfer; see the I/O methods below.
// It preserves Start's monotonic clock for idle checks. Start must not be changed
// after the tracker is published.
func (t *TrackerInfo) LastActivity() time.Time {
	return t.Start.Add(time.Duration(t.lastActivity.Load()))
}

func (t *TrackerInfo) markActivity() {
	next := int64(time.Since(t.Start))
	for previous := t.lastActivity.Load(); next > previous; previous = t.lastActivity.Load() {
		if t.lastActivity.CompareAndSwap(previous, next) {
			return
		}
	}
}

type tcpTracker struct {
	C.Conn `json:"-"`
	*TrackerInfo
	manager *Manager

	pushToManager bool `json:"-"`
	proxyTraffic  bool
}

// Classify the established outbound, never its display name or a group's
// current selection. Control, local, group and unknown types are not proxies.
func proxyEgress(kind C.AdapterType) bool {
	switch kind {
	case C.Shadowsocks, C.ShadowsocksR, C.Snell, C.Socks5, C.Http,
		C.Vmess, C.Vless, C.Trojan, C.Hysteria, C.Hysteria2, C.WireGuard,
		C.Tuic, C.Ssh, C.Mieru, C.AnyTLS, C.Sudoku, C.Masque,
		C.TrustTunnel, C.ShadowQuic, C.OpenVPN, C.Tailscale, C.ZeroTier,
		C.EasyTier, C.GostRelay:
		return true
	default:
		return false
	}
}

func (tt *tcpTracker) ID() string {
	return tt.UUID.String()
}

func (tt *tcpTracker) Info() *TrackerInfo {
	return tt.TrackerInfo
}

func (tt *tcpTracker) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	if n > 0 {
		tt.markActivity()
	}
	download := int64(n)
	if tt.pushToManager {
		tt.manager.recordTraffic(0, download, tt.proxyTraffic)
	}
	tt.DownloadTotal.Add(download)
	return n, err
}

func (tt *tcpTracker) ReadBuffer(buffer *buf.Buffer) (err error) {
	before := buffer.Len()
	err = tt.Conn.ReadBuffer(buffer)
	// Readers may append or replace contents. Empty buffers (the copy-loop
	// contract) and growth prove a read; pre-existing bytes alone do not.
	if buffer.Len() > before {
		tt.markActivity()
	}
	download := int64(buffer.Len())
	if tt.pushToManager {
		tt.manager.recordTraffic(0, download, tt.proxyTraffic)
	}
	tt.DownloadTotal.Add(download)
	return
}

func (tt *tcpTracker) UnwrapReader() (io.Reader, []N.CountFunc) {
	return tt.Conn, []N.CountFunc{func(download int64) {
		if download > 0 {
			tt.markActivity()
		}
		if tt.pushToManager {
			tt.manager.recordTraffic(0, download, tt.proxyTraffic)
		}
		tt.DownloadTotal.Add(download)
	}}
}

func (tt *tcpTracker) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	if n > 0 {
		tt.markActivity()
	}
	upload := int64(n)
	if tt.pushToManager {
		tt.manager.recordTraffic(upload, 0, tt.proxyTraffic)
	}
	tt.UploadTotal.Add(upload)
	return n, err
}

func (tt *tcpTracker) WriteBuffer(buffer *buf.Buffer) (err error) {
	upload := int64(buffer.Len())
	err = tt.Conn.WriteBuffer(buffer)
	// This API reports no byte count on failure. A partial failed write cannot
	// be confirmed here; do not treat an attempted write as activity.
	if err == nil && upload > 0 {
		tt.markActivity()
	}
	if tt.pushToManager {
		tt.manager.recordTraffic(upload, 0, tt.proxyTraffic)
	}
	tt.UploadTotal.Add(upload)
	return
}

func (tt *tcpTracker) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return tt.Conn, []N.CountFunc{func(upload int64) {
		if upload > 0 {
			tt.markActivity()
		}
		if tt.pushToManager {
			tt.manager.recordTraffic(upload, 0, tt.proxyTraffic)
		}
		tt.UploadTotal.Add(upload)
	}}
}

func (tt *tcpTracker) Close() error {
	tt.manager.Leave(tt)
	return tt.Conn.Close()
}

func (tt *tcpTracker) Upstream() any {
	return tt.Conn
}

func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *tcpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
		proxyTraffic:  proxyEgress(conn.EgressType()),
	}

	if pushToManager {
		manager.recordTraffic(uploadTotal, downloadTotal, t.proxyTraffic)
	}

	if rule != nil {
		t.TrackerInfo.Rule = rule.RuleType().String()
		t.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(t)
	return t
}

type udpTracker struct {
	C.PacketConn `json:"-"`
	*TrackerInfo
	manager *Manager

	pushToManager bool `json:"-"`
	proxyTraffic  bool
}

func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *udpTracker) Info() *TrackerInfo {
	return ut.TrackerInfo
}

func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := ut.PacketConn.ReadFrom(b)
	if n > 0 || err == nil {
		ut.markActivity()
	}
	download := int64(n)
	if ut.pushToManager {
		ut.manager.recordTraffic(0, download, ut.proxyTraffic)
	}
	ut.DownloadTotal.Add(download)
	return n, addr, err
}

func (ut *udpTracker) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = ut.PacketConn.WaitReadFrom()
	if len(data) > 0 || err == nil {
		ut.markActivity()
	}
	download := int64(len(data))
	if ut.pushToManager {
		ut.manager.recordTraffic(0, download, ut.proxyTraffic)
	}
	ut.DownloadTotal.Add(download)
	return
}

func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := ut.PacketConn.WriteTo(b, addr)
	if n > 0 || (len(b) == 0 && err == nil) {
		ut.markActivity()
	}
	upload := int64(n)
	if ut.pushToManager {
		ut.manager.recordTraffic(upload, 0, ut.proxyTraffic)
	}
	ut.UploadTotal.Add(upload)
	return n, err
}

func (ut *udpTracker) Close() error {
	ut.manager.Leave(ut)
	return ut.PacketConn.Close()
}

func (ut *udpTracker) Upstream() any {
	return ut.PacketConn
}

func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *udpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
		proxyTraffic:  proxyEgress(conn.EgressType()),
	}

	if pushToManager {
		manager.recordTraffic(uploadTotal, downloadTotal, ut.proxyTraffic)
	}

	if rule != nil {
		ut.TrackerInfo.Rule = rule.RuleType().String()
		ut.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(ut)
	return ut
}
