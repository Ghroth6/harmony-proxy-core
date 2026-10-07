package executor_test

import (
	"context"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"
	"reflect"
	"testing"
)

func TestMobilePublicationRemainsSuspendedAndDoesNotCreateListeners(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte("proxies:\n  - {name: sample, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: test-only}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.BuildMobileFixedCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	ports := listener.GetPorts()
	if err := executor.PublishMobileFixed(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if tunnel.Status() != tunnel.Suspend || !reflect.DeepEqual(listener.GetPorts(), ports) || cfg.Discard(context.Background()) == nil {
		t.Fatal("publication lost ownership or expanded listeners")
	}
	if err := executor.ActivateMobileFixed(cfg); err != nil {
		t.Fatal(err)
	}
	if tunnel.Status() != tunnel.Running {
		t.Fatal("explicit entry activation absent")
	}
	if err := executor.RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tunnel.Proxies()) != 0 || cfg.CheckCandidate() == nil {
		t.Fatal("runtime candidate not retired")
	}
}
