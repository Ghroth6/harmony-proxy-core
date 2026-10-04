package sing_tun

import (
	"testing"
	"time"

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

type blockingRuleProvider struct {
	P.RuleProvider
	entered, release chan struct{}
}

func (p *blockingRuleProvider) Name() string  { return "same" }
func (p *blockingRuleProvider) Strategy() any { return p }
func (p *blockingRuleProvider) ToIpCidr() *netipx.IPSet {
	close(p.entered)
	<-p.release
	return &netipx.IPSet{}
}

func TestTunCloseJoinsRuleUpdateAndRejectsSelectedLateCallback(t *testing.T) {
	p := &blockingRuleProvider{entered: make(chan struct{}), release: make(chan struct{})}
	l := &Listener{options: LC.Tun{RouteAddressSet: []string{"same"}}, routeProviders: map[string]P.RuleProvider{"same": p}, routeAddressMap: map[string]*netipx.IPSet{}}
	go l.ruleUpdateCallback(p)
	<-p.entered
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned before active update ended")
	case <-time.After(20 * time.Millisecond):
	}
	close(p.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join update")
	}
	delete(l.routeAddressMap, "same")
	l.ruleUpdateCallback(p)
	if len(l.routeAddressMap) != 0 {
		t.Fatal("selected callback modified closed listener")
	}
}
