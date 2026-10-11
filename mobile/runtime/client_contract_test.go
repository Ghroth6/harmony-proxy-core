package runtime_test

import (
	"encoding/json"
	"testing"

	R "github.com/metacubex/mihomo/mobile/runtime"
)

func dualClientEnvelope(t *testing.T) []byte {
	t.Helper()
	var request map[string]any
	if err := json.Unmarshal([]byte(envelope()), &request); err != nil {
		t.Fatal(err)
	}
	request["networkGeneration"] = 17
	options := request["runtimeOptions"].(map[string]any)
	options["transport"], options["udp"], options["ipv6"], options["dns"] = "tcp-udp", true, true, true
	request["platformPolicy"].(map[string]any)["addressFamily"] = "dual"
	tun := request["tunPolicy"].(map[string]any)
	tun["ipv6"] = map[string]any{"address": "fd00:111::1", "prefixLength": 126, "route": "::", "routePrefixLength": 0}
	tun["dnsServers"] = []string{"10.111.0.2", "fd00:111::2"}
	request["preparedPolicy"] = map[string]any{
		"schemaVersion": 1, "inputDigest": request["inputDigest"], "plannerVersion": "mobile-policy-1",
		"resourceManifestDigest": request["inputDigest"], "resources": []any{},
		"platformPolicyDigest": request["inputDigest"], "platform": map[string]any{"runtimeOptions": options, "platformPolicy": request["platformPolicy"], "tunPolicy": tun},
		"groupPreferencesDigest": request["inputDigest"], "groupPreferences": []any{}, "candidateDigest": request["inputDigest"],
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeStartRejectsUnknownPreparedPolicyField(t *testing.T) {
	var request map[string]any
	if err := json.Unmarshal(dualClientEnvelope(t), &request); err != nil {
		t.Fatal(err)
	}
	request["preparedPolicy"].(map[string]any)["fallbackToDirect"] = true
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = R.DecodeStart(2, 7, sample, encoded); err == nil || err.Error() != "REQUEST_FIELDS" {
		t.Fatalf("unknown prepared policy authority accepted: %v", err)
	}
}

func TestDecodeStartRejectsIncompletePreparedPolicyIdentity(t *testing.T) {
	var request map[string]any
	if err := json.Unmarshal(dualClientEnvelope(t), &request); err != nil {
		t.Fatal(err)
	}
	delete(request["preparedPolicy"].(map[string]any), "candidateDigest")
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = R.DecodeStart(2, 7, sample, encoded); err == nil || err.Error() != "REQUEST_FIELDS" {
		t.Fatalf("incomplete prepared policy identity accepted: %v", err)
	}
}

func TestDecodeStartRejectsSourcePolicyWithoutAcceptedNetworkEpoch(t *testing.T) {
	var request map[string]any
	if err := json.Unmarshal(dualClientEnvelope(t), &request); err != nil {
		t.Fatal(err)
	}
	request["networkGeneration"] = 0
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = R.DecodeStart(2, 7, sample, encoded); err == nil || err.Error() != "REQUEST_IDENTITY" {
		t.Fatalf("source policy without a real epoch accepted: %v", err)
	}
}

func TestDecodeStartAcceptsCoherentDualClientPolicyBeforeIndependentValidation(t *testing.T) {
	request, err := R.DecodeStart(2, 7, sample, dualClientEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	if request.RuntimeOptions.Transport != "tcp-udp" || !request.RuntimeOptions.DNS || !request.RuntimeOptions.IPv6 || !request.RuntimeOptions.UDP || request.PlatformPolicy.AddressFamily != "dual" {
		t.Fatal("caller client capabilities were not frozen coherently")
	}
}
