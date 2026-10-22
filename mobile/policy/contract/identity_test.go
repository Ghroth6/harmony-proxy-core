package contract_test

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy/contract"
)

func TestApplicationScopeUsesFrozenLegacyAndExplicitAllPlatformDigests(t *testing.T) {
	for _, fixture := range []struct{ canonical, digest string }{
		{`{"platformPolicy":{"addressFamily":"ipv4","applicationIds":["org.example.public"],"revision":"public-policy-v1"},"runtimeOptions":{"dns":false,"entry":"system-vpn","explicitListeners":false,"ipv6":false,"resourceDownloads":false,"transport":"tcp-udp","udp":true},"tunPolicy":{"address":"10.111.0.1","mtu":1500,"prefixLength":30,"route":"0.0.0.0","routePrefixLength":0}}`, "sha256:b53e553eb6d38b8d302c9069734edb62afbf3bb969922d2cbcdd41f3cf121c44"},
		{`{"platformPolicy":{"addressFamily":"ipv4","applicationIds":[],"applicationScope":"all","revision":"public-policy-v1"},"runtimeOptions":{"dns":false,"entry":"system-vpn","explicitListeners":false,"ipv6":false,"resourceDownloads":false,"transport":"tcp-udp","udp":true},"tunPolicy":{"address":"10.111.0.1","mtu":1500,"prefixLength":30,"route":"0.0.0.0","routePrefixLength":0}}`, "sha256:2fad48002b4ad4c17668239813df40bf9c43610e5b495afdc3f1f58ac81ff2f3"},
	} {
		var platform contract.Platform
		if err := json.Unmarshal([]byte(fixture.canonical), &platform); err != nil {
			t.Fatal(err)
		}
		prepared, err := contract.Seal(contract.Digest([]byte("public original policy")), nil, platform, nil)
		if err != nil || prepared.PlatformPolicyDigest != fixture.digest {
			t.Fatalf("scope identity differs from independently frozen SHA256 fixture: %v", err)
		}
		canonical, err := contract.CanonicalJSON(prepared.Platform)
		if err != nil || string(canonical) != fixture.canonical {
			t.Fatal("legacy absence or explicit all bytes changed")
		}
	}
}

func TestPreparedIdentityUsesCrossLanguageSortedPlatformBytes(t *testing.T) {
	platform := contract.Platform{
		RuntimeOptions: contract.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true},
		PlatformPolicy: contract.PlatformPolicy{Revision: "public-policy-v1", AddressFamily: "ipv4", ApplicationIDs: []string{}},
		TunPolicy:      contract.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500},
	}
	expected := `{"platformPolicy":{"addressFamily":"ipv4","applicationIds":[],"revision":"public-policy-v1"},"runtimeOptions":{"dns":false,"entry":"system-vpn","explicitListeners":false,"ipv6":false,"resourceDownloads":false,"transport":"tcp-udp","udp":true},"tunPolicy":{"address":"10.111.0.1","mtu":1500,"prefixLength":30,"route":"0.0.0.0","routePrefixLength":0}}`
	actual, err := contract.CanonicalJSON(platform)
	if err != nil || string(actual) != expected {
		t.Fatal("canonical platform bytes must match the independently written sorted UTF-8 fixture")
	}
	if contract.Digest(actual) != "sha256:2213facafbc2c96ea6e667f891e4890a27e8a9b276e70913680ebb1b75d7ec96" {
		t.Fatal("platform digest must match the independent host SHA-256 fixture")
	}
	inputDigest := contract.Digest([]byte("public original policy"))
	prepared, err := contract.Seal(inputDigest, nil, platform, nil)
	if err != nil || prepared.PlatformPolicyDigest != contract.Digest(actual) || prepared.ResourceManifestDigest == "" || prepared.GroupPreferencesDigest == "" || prepared.CandidateDigest == "" || prepared.Resources == nil || prepared.GroupPreferences == nil {
		t.Fatal("value seal must bind all identities and normalize empty arrays without claiming resource verification")
	}
	changed := platform
	changed.RuntimeOptions.UDP = false
	next, err := contract.Seal(inputDigest, nil, changed, nil)
	if err != nil || next.CandidateDigest == prepared.CandidateDigest || next.ResourceManifestDigest != prepared.ResourceManifestDigest {
		t.Fatal("actual runtime policy must affect the candidate independently of the original input/resources")
	}
}
