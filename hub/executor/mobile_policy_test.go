package executor_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/tunnel"
)

func TestOriginalPolicyPublicationPreservesSourceModeAndOwnedCandidate(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\nmode: direct\ndns: {enable: false}\nproxy-groups:\n - {name: PublicSelect, type: select, proxies: [DIRECT, REJECT]}\nrules:\n - DOMAIN,documentation.example,REJECT\n - MATCH,PublicSelect\n")
	plan := engine.Plan("publication-plan", input, nil)
	platform := contract.Platform{RuntimeOptions: contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true}, PlatformPolicy: contract.PlatformPolicy{Revision: "public-policy-v1", AddressFamily: "ipv4", ApplicationIDs: []string{}}, TunPolicy: contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}}
	prepared, err := contract.Seal(plan.InputDigest, nil, platform, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	ports := listener.GetPorts()
	if err := executor.PublishMobilePolicy(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if tunnel.Status() != tunnel.Suspend || tunnel.Mode() != tunnel.Direct || tunnel.FindProcessMode() != process.FindProcessStrict || len(tunnel.Rules()) != 2 || !reflect.DeepEqual(ports, listener.GetPorts()) || cfg.Discard(context.Background()) == nil {
		t.Fatal("original publication must preserve source behavior, transfer ownership and defer ingress/listeners")
	}
	if err := executor.ActivateMobilePolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if err := executor.RetireConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cfg.CheckCandidate() == nil || len(tunnel.Proxies()) != 0 {
		t.Fatal("actual original candidate must retire and reject historical reuse")
	}
}
