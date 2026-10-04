// Package platformnetwork publishes complete network observations from a host
// platform which cannot expose its interfaces and DNS through Go's OS APIs.
package platformnetwork

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

var ErrStaleGeneration = errors.New("platform network generation is not newer")

// Snapshot is a single observation of the underlying network, never the VPN's
// virtual interface. Generation is allocated before asynchronous collection.
// Index must be a verified OS interface index; zero means unknown, not NetworkID.
type Snapshot struct {
	Generation uint64      `json:"generation"`
	NetworkID  int64       `json:"networkId"`
	Online     bool        `json:"online"`
	DNS        []string    `json:"dns"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index,omitempty"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
	Routes    []Route  `json:"routes"`
}

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
}

type store struct{ value atomic.Pointer[Snapshot] }

var current store

// Publish validates and copies the entire observation before atomic publication.
// Invalid, equal or older generations leave the current observation unchanged.
// Publishing an offline observation does not restore native DNS or enumeration.
func Publish(snapshot Snapshot) error { return current.publish(snapshot) }

func (s *store) publish(snapshot Snapshot) error {
	next, err := validate(snapshot)
	if err != nil {
		return err
	}
	for {
		previous := s.value.Load()
		if previous != nil && next.Generation <= previous.Generation {
			return ErrStaleGeneration
		}
		if s.value.CompareAndSwap(previous, &next) {
			return nil
		}
	}
}

// Current returns an independent copy. On OHOS, absence of the first snapshot
// is an empty offline observation; native enumeration is never a fallback.
func Current() (Snapshot, bool) {
	if snapshot := current.value.Load(); snapshot != nil {
		return clone(*snapshot), true
	}
	return Snapshot{}, required
}

// Generation is also the cache namespace. In-flight work from an older network
// may finish, but must not populate caches or join work in the new namespace.
func Generation() (uint64, bool) {
	if snapshot := current.value.Load(); snapshot != nil {
		return snapshot.Generation, true
	}
	return 0, required
}

func clone(snapshot Snapshot) Snapshot {
	snapshot.DNS = append([]string(nil), snapshot.DNS...)
	snapshot.Interfaces = append([]Interface(nil), snapshot.Interfaces...)
	for i := range snapshot.Interfaces {
		snapshot.Interfaces[i].Addresses = append([]string(nil), snapshot.Interfaces[i].Addresses...)
		snapshot.Interfaces[i].Routes = append([]Route(nil), snapshot.Interfaces[i].Routes...)
	}
	return snapshot
}

func validate(snapshot Snapshot) (Snapshot, error) {
	if snapshot.Generation == 0 || snapshot.NetworkID < 0 {
		return Snapshot{}, errors.New("network generation must be positive and networkId nonnegative")
	}
	if !snapshot.Online && (len(snapshot.DNS) != 0 || len(snapshot.Interfaces) != 0) {
		return Snapshot{}, errors.New("offline network must have no DNS or interfaces")
	}
	if snapshot.Online && len(snapshot.Interfaces) == 0 {
		return Snapshot{}, errors.New("online network must include its interfaces")
	}
	snapshot = clone(snapshot)
	for i, endpoint := range snapshot.DNS {
		address, err := netip.ParseAddrPort(endpoint)
		if err != nil {
			ip, ipErr := netip.ParseAddr(endpoint)
			if ipErr != nil {
				return Snapshot{}, fmt.Errorf("invalid DNS endpoint %q", endpoint)
			}
			address = netip.AddrPortFrom(ip, 53)
		}
		if address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return Snapshot{}, fmt.Errorf("invalid DNS endpoint %q", endpoint)
		}
		snapshot.DNS[i] = address.String()
	}
	names := make(map[string]bool)
	indices := make(map[int]bool)
	for i := range snapshot.Interfaces {
		iface := &snapshot.Interfaces[i]
		if iface.Name == "" || strings.TrimSpace(iface.Name) != iface.Name || strings.ContainsAny(iface.Name, "\x00/\\") || names[iface.Name] {
			return Snapshot{}, fmt.Errorf("invalid or duplicate interface name %q", iface.Name)
		}
		if iface.Index < 0 || iface.MTU < 0 || (iface.Index > 0 && indices[iface.Index]) {
			return Snapshot{}, fmt.Errorf("invalid interface index or MTU for %q", iface.Name)
		}
		names[iface.Name] = true
		indices[iface.Index] = true
		for j, address := range iface.Addresses {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
				return Snapshot{}, fmt.Errorf("invalid interface address %q", address)
			}
			// Preserve the host bits: they identify the actual interface address.
			iface.Addresses[j] = prefix.String()
		}
		for j := range iface.Routes {
			route := &iface.Routes[j]
			prefix, err := netip.ParsePrefix(route.Destination)
			if err != nil || prefix.Addr().Is4In6() {
				return Snapshot{}, fmt.Errorf("invalid route destination %q", route.Destination)
			}
			route.Destination = prefix.Masked().String()
			if route.Gateway != "" {
				gateway, err := netip.ParseAddr(route.Gateway)
				if err != nil || gateway.IsMulticast() || gateway.Is4In6() || gateway.Is4() != prefix.Addr().Is4() {
					return Snapshot{}, fmt.Errorf("invalid route gateway %q", route.Gateway)
				}
				route.Gateway = gateway.String()
			}
		}
	}
	return snapshot, nil
}
