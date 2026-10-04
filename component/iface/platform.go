package iface

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/platformnetwork"
)

func platformCache(snapshot platformnetwork.Snapshot) *ifaceCache {
	cache := &ifaceCache{
		ifMapByName: make(map[string]*Interface),
		ifMapByAddr: make(map[netip.Addr]*Interface),
	}
	// The validated snapshot is already a private copy. Do not consult anet or
	// net.Interface.Addrs, and do not put it behind the native 20-second cache.
	for _, item := range snapshot.Interfaces {
		iface := &Interface{Name: item.Name, Index: item.Index, MTU: item.MTU}
		if item.Up {
			iface.Flags = net.FlagUp
		}
		for _, address := range item.Addresses {
			iface.Addresses = append(iface.Addresses, netip.MustParsePrefix(address))
		}
		cache.ifMapByName[iface.Name] = iface
		if !item.Up {
			continue
		}
		for _, prefix := range iface.Addresses {
			cache.ifMapByAddr[prefix.Addr()] = iface
			cache.ifTable.Insert(prefix, iface)
		}
		for _, route := range item.Routes {
			cache.ifTable.Insert(netip.MustParsePrefix(route.Destination), iface)
		}
	}
	return cache
}
