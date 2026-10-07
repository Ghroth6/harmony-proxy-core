package config_test

import (
	"context"
	"github.com/metacubex/mihomo/config"
	"testing"
)

func TestMobileFixedCandidateHasIndependentOwnedResources(t *testing.T) {
	input := []byte("proxies:\n  - {name: sample, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: test-only}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n")
	raw, err := config.UnmarshalRawConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.BuildMobileFixedCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.BuildMobileFixedCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Discard(context.Background())
	if first.SharesCandidate(second) || len(first.Rules) != 1 || first.General.IPv6 || first.General.Port != 0 {
		t.Fatal("candidate reused or expanded capabilities")
	}
	if err := first.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.CheckCandidate() == nil || second.CheckCandidate() != nil {
		t.Fatal("discard changed independent runtime candidate")
	}
}
