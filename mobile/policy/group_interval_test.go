package policy_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"go.yaml.in/yaml/v3"
)

func TestOriginalGroupNumericIntervalMatchesPinnedDecoderWithoutRewritingInput(t *testing.T) {
	for _, kind := range []string{"select", "url-test", "fallback"} {
		for _, test := range []struct {
			name, field string
			interval    int
		}{
			{name: "omitted"},
			{name: "integer", field: "interval: 300", interval: 300},
			{name: "zero-integer", field: "interval: 0"},
			{name: "decimal-string", field: "interval: '300'", interval: 300},
			{name: "zero-string", field: "interval: '0'"},
			{name: "plus-string", field: "interval: '+300'", interval: 300},
			{name: "hex-string", field: "interval: '0x12c'", interval: 300},
			{name: "binary-string", field: "interval: '0b100101100'", interval: 300},
			{name: "octal-string", field: "interval: '0300'", interval: 192},
			{name: "separator-string", field: "interval: '3_00'", interval: 300},
			{name: "duration-boundary", field: "interval: '9223372036'", interval: 9223372036},
			{name: "duration-boundary-int", field: "interval: 9223372036", interval: 9223372036},
		} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				engine, err := policy.NewEngine(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := engine.Close(); err != nil {
						t.Error("actual candidate owners must release the trusted root")
					}
				}()
				baseline := engine.ResourceAcquireCount()
				field := ""
				if test.field != "" {
					field = ", " + test.field
				}
				raw := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nproxy-groups:\n - {name: PublicNumeric, type: %s, proxies: [REJECT, DIRECT], url: 'http://documentation.example/probe', lazy: true%s}\nrules: ['MATCH,PublicNumeric']\n", kind, field))
				original := bytes.Clone(raw)
				var parsed struct {
					Groups []map[string]any `yaml:"proxy-groups"`
				}
				if err := yaml.Unmarshal(raw, &parsed); err != nil || len(parsed.Groups) != 1 {
					t.Fatal("public original fixture must decode without normalization")
				}
				decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
				var upstream outboundgroup.GroupCommonOption
				if err := decoder.Decode(parsed.Groups[0], &upstream); err != nil || upstream.Interval != test.interval {
					t.Fatal("the pinned upstream decoder must accept this exact original representation")
				}
				plan := engine.Plan("numeric-group-plan", raw, nil)
				if plan.Category != "planned" || plan.Code != "" || !plan.ResourcesComplete || len(plan.Requirements) != 0 {
					t.Errorf("upstream-valid interval must plan without acquisition: %s/%s", plan.Category, plan.Code)
				}
				if plan.InputDigest != contract.Digest(original) || len(plan.Groups) != 1 || len(plan.Groups[0].Members) != 2 || plan.Groups[0].Members[0].DisplayName != "REJECT" || plan.Groups[0].Members[1].DisplayName != "DIRECT" {
					t.Error("original bytes and declared member order must remain authoritative")
				}
				prepared, err := contract.Seal(contract.Digest(raw), nil, publicPlatform(), nil)
				if err != nil {
					t.Fatal(err)
				}
				validated := engine.Validate("numeric-group-validate", raw, prepared)
				if validated.Category != "pass" || validated.Code != "" || validated.CandidateDigest != prepared.CandidateDigest || validated.ResourceManifestDigest != prepared.ResourceManifestDigest {
					t.Errorf("upstream-valid interval must validate the unchanged identity: %s/%s", validated.Category, validated.Code)
				}
				candidate, err := engine.BuildCandidate(raw, prepared)
				if candidate != nil {
					defer func() {
						if err := candidate.Discard(context.Background()); err != nil {
							t.Error("actual group/provider owners must discard without network")
						}
					}()
				}
				if err != nil || candidate == nil {
					t.Errorf("upstream-valid interval must construct independently: %v", err)
				} else {
					accepted, ok := candidate.MobilePolicyContext()
					if !ok || accepted.CandidateDigest != prepared.CandidateDigest || accepted.ResourceManifestDigest != prepared.ResourceManifestDigest || accepted.InputDigest != contract.Digest(original) || len(candidate.Rules) != 1 || candidate.Rules[0].Adapter() != "PublicNumeric" {
						t.Error("real candidate must keep raw/resource identity and original routing")
					}
					health, ok := candidate.Providers["PublicNumeric"].(interface{ HealthCheckEnabled() bool })
					if !ok || health.HealthCheckEnabled() != (test.interval != 0 || kind != "select") {
						t.Error("zero and omitted interval must preserve actual upstream group defaults")
					}
				}
				if !bytes.Equal(raw, original) || engine.ResourceAcquireCount() != baseline {
					t.Error("preparation must preserve source bytes and acquire no resource")
				}
			})
		}
	}
}

func TestOriginalNumericStringGroupIntervalActivatesProtectedTimerAndRetires(t *testing.T) {
	var requests, protected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" || r.URL.Path != "/numeric-interval" {
			t.Error("original health request method/path must remain intact")
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error("normal retirement must release the actual trusted root")
		}
	})
	baseline := engine.ResourceAcquireCount()
	raw := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nproxy-groups:\n - {name: PublicNumeric, type: fallback, proxies: [DIRECT], url: '%s/numeric-interval', interval: '1', lazy: false}\nrules: ['MATCH,PublicNumeric']\n", server.URL))
	plan := engine.Plan("numeric-group-timer-plan", raw, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete {
		t.Fatalf("original numeric string must plan: %s/%s", plan.Category, plan.Code)
	}
	prepared, err := contract.Seal(plan.InputDigest, nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result := engine.Validate("numeric-group-timer-validate", raw, prepared); result.Category != "pass" {
		t.Fatalf("actual group construction/cleanup must pass: %s", result.Code)
	}
	candidate, err := engine.BuildCandidate(raw, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("pure Plan/Validate/Build must not start health traffic")
	}
	activatePublicPolicy(t, candidate, []string{}, &protected, true)
	if requests.Load() != 0 {
		t.Fatal("publication must not activate the original timer")
	}
	if err := executor.ActivateMobilePolicy(candidate); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for requests.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if requests.Load() != 1 || protected.Load() == 0 {
		t.Fatal("explicit activation must start a real protected original health request")
	}
	time.Sleep(600 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatal("numeric string must not become a faster or zero interval")
	}
	deadline = time.Now().Add(1400 * time.Millisecond)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if requests.Load() != 2 {
		t.Fatal("numeric string must retain the original one-second periodic timer")
	}
	candidate.CancelMobilePolicyServices()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := candidate.WaitMobilePolicyServices(wait); err != nil {
		t.Fatal(err)
	}
	stopped := requests.Load()
	time.Sleep(1100 * time.Millisecond)
	if requests.Load() != stopped || engine.ResourceAcquireCount() != baseline {
		t.Fatal("normal retirement must join the real timer without further traffic or resource acquisition")
	}
}

func TestOriginalGroupNumericIntervalRejectsInvalidValuesAcrossPolicyBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, field, code string
	}{
		{name: "negative", field: "interval: '-1'", code: "GROUP_INVALID"},
		{name: "native-int-overflow", field: "interval: '9223372036854775808'", code: "GROUP_INVALID"},
		{name: "duration-overflow-string", field: "interval: '9223372037'", code: "GROUP_INVALID"},
		{name: "duration-overflow-int", field: "interval: 9223372037", code: "GROUP_INVALID"},
		{name: "fraction", field: "interval: '1.5'", code: "GROUP_INVALID"},
		{name: "leading-space", field: "interval: ' 300'", code: "GROUP_INVALID"},
		{name: "empty", field: "interval: ''", code: "GROUP_INVALID"},
		{name: "invalid-octal", field: "interval: '08'", code: "GROUP_INVALID"},
		{name: "invalid-digits", field: "interval: 'documentation'", code: "GROUP_INVALID"},
		{name: "boolean", field: "interval: true", code: "GROUP_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := engine.Close(); err != nil {
					t.Error("failed preparation must release all actual owners")
				}
			}()
			baseline := engine.ResourceAcquireCount()
			raw := []byte("ipv6: false\ndns: {enable: false}\nproxy-groups:\n - {name: PublicNumeric, type: url-test, proxies: [REJECT, DIRECT], lazy: true, " + test.field + "}\nrules: ['MATCH,PublicNumeric']\n")
			plan := engine.Plan("numeric-group-negative-plan", raw, nil)
			if plan.Category == "planned" || plan.Code != test.code {
				t.Errorf("invalid or unimplemented group value must fail the pure plan: %s/%s", plan.Category, plan.Code)
			}
			prepared, err := contract.Seal(contract.Digest(raw), nil, publicPlatform(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if validated := engine.Validate("numeric-group-negative-validate", raw, prepared); validated.Category == "pass" || validated.Code != test.code || validated.CandidateDigest != "" {
				t.Errorf("validation must retain the exact refusal: %s/%s", validated.Category, validated.Code)
			}
			candidate, err := engine.BuildCandidate(raw, prepared)
			if candidate != nil {
				if cleanup := candidate.Discard(context.Background()); cleanup != nil {
					t.Error("unexpected candidate must still be discarded")
				}
			}
			if candidate != nil || err == nil || err.Error() != test.code || engine.ResourceAcquireCount() != baseline {
				t.Errorf("independent build must refuse before acquisition: candidate=%t, error=%v", candidate != nil, err)
			}
		})
	}
}
