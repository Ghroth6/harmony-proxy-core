package config

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/ntp/ntp"
)

func (c *Config) prepareMobileNTP() {
	if c.NTP == nil || !c.NTP.Enable || c.NTP.Server == "" || c.NTP.Interval <= 0 {
		return
	}
	var physical C.Dialer = c.mobileNetwork.newPhysical(nil)
	if c.NTP.DialerProxy != "" {
		physical = proxydialer.NewByNameWithLookup(c.NTP.DialerProxy, &mobilePolicyProxyLookup{candidate: c})
	}
	c.mobileNTP = ntp.NewOwnedService(net.JoinHostPort(c.NTP.Server, strconv.Itoa(c.NTP.Port)), time.Duration(c.NTP.Interval), physical, c.NTP.WriteToSystem)
}

func (c *Config) activateMobileNTP(root context.Context) error {
	if c.mobileNTP == nil {
		return nil
	}
	root = forwarding.SnapshotManagementNetwork(root)
	if c.mobilePolicyResources != nil {
		if owner, ok := c.mobilePolicyResources.Services.(dialer.WorkerOwner); ok {
			root = dialer.WithWorkerOwner(root, owner)
		}
	}
	return c.mobileNTP.Activate(root)
}
