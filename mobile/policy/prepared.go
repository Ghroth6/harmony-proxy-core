package policy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/validation"
	"reflect"
)

type PreparedReceipt struct {
	SchemaVersion          int                     `json:"schemaVersion"`
	OperationID            string                  `json:"operationId"`
	InputDigest            string                  `json:"inputDigest"`
	Category               string                  `json:"category"`
	Code                   string                  `json:"code"`
	ResourceManifestDigest string                  `json:"resourceManifestDigest"`
	PlatformPolicyDigest   string                  `json:"platformPolicyDigest"`
	GroupPreferencesDigest string                  `json:"groupPreferencesDigest"`
	CandidateDigest        string                  `json:"candidateDigest"`
	Covered                []string                `json:"covered"`
	Uncovered              []string                `json:"uncovered"`
	CoreIdentity           validation.CoreIdentity `json:"coreIdentity"`
}

func (e *Engine) Validate(operationID string, input []byte, prepared contract.PreparedContext) (receipt PreparedReceipt) {
	receipt = PreparedReceipt{SchemaVersion: contract.Version, OperationID: operationID, InputDigest: contract.Digest(input), Category: "failure", Code: "POLICY_FAILURE", Covered: []string{}, Uncovered: []string{}, CoreIdentity: validation.Identity()}
	defer func() {
		if recover() != nil {
			receipt.Category = "failure"
			receipt.Code = "POLICY_FAILURE"
			receipt.ResourceManifestDigest = ""
			receipt.PlatformPolicyDigest = ""
			receipt.GroupPreferencesDigest = ""
			receipt.CandidateDigest = ""
		}
	}()
	if !safeOperation(operationID) {
		receipt.Code = "POLICY_REQUEST_BOUNDS"
		return
	}
	candidate, err := e.BuildCandidate(input, prepared)
	if candidate != nil {
		if cleanup := candidate.Discard(context.Background()); cleanup != nil {
			e.retainCandidate(candidate, cleanup)
			receipt.Code = "POLICY_CLEANUP_FAILED"
			return
		}
	}
	if err != nil {
		receipt.Category = "invalid"
		receipt.Code = err.Error()
		var diagnostic *config.MobileValidationError
		if errors.As(err, &diagnostic) {
			receipt.Code = diagnostic.Code
		}
		return
	}
	receipt.Category = "pass"
	receipt.Code = ""
	receipt.ResourceManifestDigest = prepared.ResourceManifestDigest
	receipt.PlatformPolicyDigest = prepared.PlatformPolicyDigest
	receipt.GroupPreferencesDigest = prepared.GroupPreferencesDigest
	receipt.CandidateDigest = prepared.CandidateDigest
	receipt.Covered = []string{"original-source-policy-ipv4-v1", "original-rules-and-groups", "verified-prepared-identities", "candidate-resources-closed"}
	if prepared.Platform.RuntimeOptions.IPv6 {
		receipt.Covered[0] = "original-source-policy-dual-v1"
	}
	receipt.Uncovered = []string{"runtime-connectivity"}
	plan := e.Plan(operationID, input, prepared.Resources)
	for _, adaptation := range plan.Adaptations {
		if adaptation.Code == "PROCESS_LOOKUP_UNVERIFIED" {
			receipt.Uncovered = append(receipt.Uncovered, "ohos-process-owner-lookup")
			break
		}
	}
	return
}

func (e *Engine) BuildCandidate(input []byte, prepared contract.PreparedContext) (*config.Config, error) {
	verified, code := e.verify(input, prepared)
	if code != "" {
		return nil, errors.New(code)
	}
	inputs, err := e.prepareProviders(verified.raw, verified.context, verified.plan.Requirements, verified.fixed)
	if err != nil {
		if cleanup := discardPreparedProviders(inputs); cleanup != nil {
			return nil, errors.New("POLICY_CLEANUP_FAILED")
		}
		return nil, err
	}
	return config.BuildMobilePolicyCandidate(verified.raw, verified.context, verified.preferences, inputs)
}

type preparedVerification struct {
	context     contract.PreparedContext
	raw         *config.RawConfig
	preferences map[string]string
	plan        PlanReceipt
	fixed       map[string]fixedResource
}

func (e *Engine) verify(input []byte, prepared contract.PreparedContext) (*preparedVerification, string) {
	encoded, err := json.Marshal(prepared)
	if err != nil || len(encoded) > contract.MaxControlBytes || len(input) > contract.MaxControlBytes {
		return nil, "POLICY_REQUEST_BOUNDS"
	}
	if prepared.SchemaVersion != contract.Version || prepared.PlannerVersion != contract.PlannerVersion || prepared.InputDigest != contract.Digest(input) {
		return nil, "POLICY_IDENTITY_INVALID"
	}
	sealed, err := contract.Seal(prepared.InputDigest, prepared.Resources, prepared.Platform, prepared.GroupPreferences)
	if err != nil || sealed.CandidateDigest != prepared.CandidateDigest || sealed.ResourceManifestDigest != prepared.ResourceManifestDigest || sealed.PlatformPolicyDigest != prepared.PlatformPolicyDigest || sealed.GroupPreferencesDigest != prepared.GroupPreferencesDigest {
		return nil, "POLICY_IDENTITY_INVALID"
	}
	var fixed map[string]fixedResource
	plan := e.plan("policy-independent-build", input, prepared.Resources, &fixed)
	if plan.Category != "planned" {
		return nil, plan.Code
	}
	if !plan.ResourcesComplete {
		return nil, "POLICY_RESOURCES_MISSING"
	}
	raw, _, code := decodePolicy(input)
	if code != "" {
		return nil, code
	}
	if !policyPlatform(raw, plan, prepared.Platform) {
		return nil, "POLICY_PLATFORM_INVALID"
	}
	preferences := map[string]string{}
	for _, preference := range prepared.GroupPreferences {
		matched := false
		for _, group := range plan.Groups {
			if group.GroupRef != preference.GroupRef {
				continue
			}
			if group.Type != "select" {
				return nil, "POLICY_GROUP_PREFERENCE_INVALID"
			}
			for _, member := range group.Members {
				if member.MemberRef != preference.MemberRef {
					continue
				}
				name, _ := raw.ProxyGroup[group.Position-1]["name"].(string)
				members := raw.ProxyGroup[group.Position-1]["proxies"].([]any)
				preferences[name] = members[member.Position-1].(string)
				matched = true
			}
		}
		if !matched {
			return nil, "POLICY_GROUP_PREFERENCE_INVALID"
		}
	}
	return &preparedVerification{context: sealed, raw: raw, preferences: preferences, plan: plan, fixed: fixed}, ""
}

func policyPlatform(raw *config.RawConfig, plan PlanReceipt, platform contract.Platform) bool {
	periodic := false
	for _, requirement := range plan.Requirements {
		if requirement.IntervalSeconds > 0 && (requirement.SourceKind == "http" || requirement.SourceKind == "engine-default") {
			periodic = true
		}
	}
	expected := contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", DNS: raw.DNS.Enable, IPv6: raw.IPv6, UDP: true, ResourceDownloads: periodic}
	if platform.RuntimeOptions != expected || !safeOperation(platform.PlatformPolicy.Revision) || len(platform.PlatformPolicy.ApplicationIDs) > 4096 {
		return false
	}
	family := "ipv4"
	if raw.IPv6 {
		family = "dual"
	}
	if platform.PlatformPolicy.AddressFamily != family {
		return false
	}
	tun := contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}
	if raw.IPv6 {
		tun.IPv6 = &contract.IPv6Policy{Address: "fd00:111::1", PrefixLength: 126, Route: "::"}
	}
	if raw.DNS.Enable {
		tun.DNSServers = []string{"10.111.0.2"}
		if raw.IPv6 {
			tun.DNSServers = append(tun.DNSServers, "fd00:111::2")
		}
	}
	actual := platform.TunPolicy
	if len(actual.DNSServers) == 0 {
		actual.DNSServers = nil
	}
	return reflect.DeepEqual(actual, tun)
}
