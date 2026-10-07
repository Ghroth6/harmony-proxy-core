package validation

import (
	"github.com/metacubex/mihomo/config"
	"net/netip"
	"strings"
)

// Called only after the original-field gate, actual static constructors, rule
// validation and temporary-resource retirement succeeded. This token describes
// configuration bytes only, never platform readiness or runtime options.
func fixedRuntimeScope(raw *config.RawConfig) bool {
	if len(raw.Proxy) != 1 || len(raw.ProxyGroup) != 1 || len(raw.Rule) != 1 {
		return false
	}
	node, group := raw.Proxy[0], raw.ProxyGroup[0]
	server, ok := node["server"].(string)
	if !ok {
		return false
	}
	address, err := netip.ParseAddr(server)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if node["password"] == "" {
		return false
	}
	if udp, present := node["udp"]; present && udp != false {
		return false
	}
	members, ok := group["proxies"].([]any)
	if !ok || len(members) != 1 || members[0] != node["name"] {
		return false
	}
	parts := strings.Split(raw.Rule[0], ",")
	return len(parts) == 2 && strings.TrimSpace(parts[0]) == "MATCH" && strings.TrimSpace(parts[1]) == group["name"]
}
