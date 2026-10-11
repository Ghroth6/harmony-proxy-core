package policy_test

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestOriginalPolicyVMessPacketEncodingChecksPlanValidateAndIndependentBuild(t *testing.T) {
	for _, test := range []struct {
		name, field, category, code string
	}{
		{name: "omitted", category: "planned"},
		{name: "empty", field: "packet-encoding: ''", category: "planned"},
		{name: "packetaddr", field: "packet-encoding: packetaddr", category: "planned"},
		{name: "packet-alias", field: "packet-encoding: packet", category: "planned"},
		{name: "xudp", field: "packet-encoding: xudp", category: "planned"},
		{name: "unknown", field: "packet-encoding: documentation-unknown", category: "unsupported", code: "CAPABILITY_NOT_COVERED"},
		{name: "wrong-type", field: "packet-encoding: true", category: "invalid", code: "PROXY_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := engine.Close(); err != nil {
					t.Error("all actual candidate owners must retire before the trusted root closes")
				}
			}()
			baseline := engine.ResourceAcquireCount()
			field := ""
			if test.field != "" {
				field = ", " + test.field
			}
			raw := []byte("ipv6: false\ndns: {enable: false}\nproxies:\n - {name: Documentation, type: vmess, server: 192.0.2.1, port: 443, uuid: 00000000-0000-4000-8000-000000000001, alterId: 0, cipher: auto, udp: true" + field + "}\nproxy-groups:\n - {name: PublicSelect, type: select, proxies: [Documentation]}\nrules: ['MATCH,PublicSelect']\n")
			plan := engine.Plan("vmess-packet-plan", raw, nil)
			if plan.Category != test.category || plan.Code != test.code {
				t.Errorf("plan must reject unknown original connection values: got %s/%s, want %s/%s", plan.Category, plan.Code, test.category, test.code)
			}
			prepared, err := contract.Seal(contract.Digest(raw), nil, publicPlatform(), nil)
			if err != nil {
				t.Fatal(err)
			}
			validation := engine.Validate("vmess-packet-validate", raw, prepared)
			candidate, buildErr := engine.BuildCandidate(raw, prepared)
			if candidate != nil {
				defer func() {
					if err := candidate.Discard(context.Background()); err != nil {
						t.Error("actual adapter and preparation owners must close")
					}
				}()
			}
			if test.category == "planned" {
				if validation.Category != "pass" || validation.Code != "" || validation.CandidateDigest != prepared.CandidateDigest || validation.InputDigest != contract.Digest(raw) || candidate == nil || buildErr != nil {
					t.Fatalf("implemented value must validate and construct independently: %s/%s, build=%v", validation.Category, validation.Code, buildErr)
				}
				proxy := candidate.Proxies["Documentation"]
				if proxy == nil || !proxy.SupportUDP() {
					t.Fatal("constructed candidate must retain original VMess UDP support")
				}
				if proxy.Type() != C.Vmess {
					t.Fatal("success must use the real pinned VMess adapter")
				}
				if len(candidate.Rules) != 1 || candidate.Rules[0].Adapter() != "PublicSelect" {
					t.Error("original group and route must remain intact")
				}
			} else {
				if validation.Category == "pass" || validation.Code != test.code || validation.CandidateDigest != "" {
					t.Errorf("validation must refuse the same original parameter: %s/%s", validation.Category, validation.Code)
				}
				if candidate != nil || buildErr == nil || buildErr.Error() != test.code {
					t.Errorf("runtime construction must not silently use a default: candidate=%t, error=%v", candidate != nil, buildErr)
				}
			}
			if engine.ResourceAcquireCount() != baseline {
				t.Error("planning, construction and discard must not acquire any resource")
			}
		})
	}
}
