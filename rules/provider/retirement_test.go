package provider

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type notificationTunnel struct {
	P.Tunnel
	callback *utils.Callback[P.RuleProvider]
}

func (n notificationTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] { return n.callback }

func TestRuleProviderRetirementJoinsSelectedNotificationWithoutBlockingCancel(t *testing.T) {
	previous := tunnel
	defer func() { tunnel = previous }()
	callback := utils.NewCallback[P.RuleProvider]()
	SetTunnel(notificationTunnel{callback: callback})
	vehicle := resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules.yaml"))
	p := NewRuleSetProvider("same", P.Domain, P.YamlRule, 0, vehicle, nil, nil, nil).(*RuleSetProvider)
	entered, release := make(chan P.RuleProvider, 1), make(chan struct{})
	closer := callback.Register(func(owner P.RuleProvider) { entered <- owner; <-release })
	defer closer.Close()
	if _, _, err := p.SideUpdate([]byte("payload:\n  - example.com\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case owner := <-entered:
		if owner != p {
			t.Fatal("notification lost provider identity")
		}
	case <-time.After(time.Second):
		t.Fatal("notification not selected")
	}
	cancelled := make(chan struct{})
	go func() { p.Cancel(); close(cancelled) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("observer blocked cancellation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := p.Wait(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("observer was not joined: %v", err)
	}
	close(release)
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.SideUpdate([]byte("payload:\n  - late.example\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired update admitted: %v", err)
	}
}
