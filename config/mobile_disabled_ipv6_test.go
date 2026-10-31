package config_test

import (
	"context"
	"testing"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestMobileDisabledIPv6UsesUpstreamDNSNormalization(t *testing.T) {
	for _, addressRange := range []string{"not-a-prefix", "fd00:123::/120"} {
		t.Run(addressRange, func(t *testing.T) {
			raw := config.DefaultRawConfig()
			raw.IPv6, raw.DNS.Enable = false, true
			raw.DNS.FakeIPRange6 = addressRange
			candidate, err := config.BuildMobilePolicyCandidate(raw, contract.PreparedContext{}, nil)
			if candidate != nil {
				defer func() {
					if err := candidate.Discard(context.Background()); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatalf("disabled IPv6 DNS range must not reject the candidate: %v", err)
			}
			if candidate.DNS.FakeIPRange6.IsValid() || candidate.DNS.FakeIPPool6 != nil {
				t.Fatal("disabled IPv6 retained a fake-IP range or pool")
			}
		})
	}
	// An enabled, malformed range must still use the official DNS validation.
	raw := config.DefaultRawConfig()
	raw.IPv6, raw.DNS.Enable = true, true
	raw.DNS.FakeIPRange6 = "not-a-prefix"
	candidate, err := config.BuildMobilePolicyCandidate(raw, contract.PreparedContext{}, nil)
	if candidate != nil {
		defer func() {
			if err := candidate.Discard(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	if err == nil {
		t.Fatal("enabled invalid IPv6 DNS range bypassed official validation")
	}
}
