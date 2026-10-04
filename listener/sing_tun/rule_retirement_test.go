package sing_tun

import (
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	RP "github.com/metacubex/mihomo/rules/provider"
	"go4.org/netipx"
)

func TestRuleNotificationRejectsRetiredSameNameProvider(t *testing.T) {
	old := RP.NewInlineProvider("same", P.IPCIDR, []string{"10.0.0.0/8"}, nil)
	next := RP.NewInlineProvider("same", P.IPCIDR, []string{"192.168.0.0/16"}, nil)
	l := &Listener{options: LC.Tun{RouteAddressSet: []string{"same"}}, routeProviders: map[string]P.RuleProvider{"same": next}, routeAddressMap: map[string]*netipx.IPSet{}}
	l.ruleUpdateCallback(old)
	if len(l.routeAddressMap) != 0 {
		t.Fatal("old same-name provider updated new listener")
	}
	l.ruleUpdateCallback(next)
	if len(l.routeAddressMap) != 1 {
		t.Fatal("current provider notification rejected")
	}
}
