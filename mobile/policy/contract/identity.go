package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

func Digest(input []byte) string {
	hash := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// CanonicalJSON sorts every object key while preserving arrays and exact
// integers. Identity-bearing strings are restricted to ASCII by Seal, avoiding
// language-specific Unicode escaping in the application/native boundary.
func CanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(&buffer)
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	buffer.Reset()
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func IsDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func identityASCII(value string) bool {
	for _, r := range value {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// Seal computes value identities only. The policy Engine must independently
// verify source semantics and the actual trusted resource bytes before use.
func Seal(inputDigest string, resources []Resource, platform Platform, preferences []Preference) (PreparedContext, error) {
	invalid := errors.New("policy identity invalid")
	if !IsDigest(inputDigest) || len(resources) > MaxResources || len(preferences) > MaxGroups {
		return PreparedContext{}, invalid
	}
	resources = append([]Resource{}, resources...)
	preferences = append([]Preference{}, preferences...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].RefID < resources[j].RefID })
	sort.Slice(preferences, func(i, j int) bool { return preferences[i].GroupRef < preferences[j].GroupRef })
	var total int64
	for index, resource := range resources {
		if !IsDigest(resource.RefID) || !IsDigest(resource.SourceDigest) || !IsDigest(resource.ContentDigest) || resource.ByteLength <= 0 || resource.ByteLength > MaxBinaryBytes || !identityASCII(resource.Kind) || !identityASCII(resource.Format) || !identityASCII(resource.RelativePath) || index > 0 && resources[index-1].RefID == resource.RefID {
			return PreparedContext{}, invalid
		}
		total += resource.ByteLength
	}
	if total > MaxTotalBytes {
		return PreparedContext{}, invalid
	}
	for index, preference := range preferences {
		if !IsDigest(preference.GroupRef) || !IsDigest(preference.MemberRef) || index > 0 && preferences[index-1].GroupRef == preference.GroupRef {
			return PreparedContext{}, invalid
		}
	}
	if platform.PlatformPolicy.ApplicationIDs == nil {
		platform.PlatformPolicy.ApplicationIDs = []string{}
	}
	encodedPlatform, err := CanonicalJSON(platform)
	if err != nil || !identityASCII(string(encodedPlatform)) {
		return PreparedContext{}, invalid
	}
	// JSON escapes non-ASCII only for U+2028/U+2029; validate the input strings too.
	if !identityASCII(platform.PlatformPolicy.Revision) || !identityASCII(platform.PlatformPolicy.AddressFamily) || !identityASCII(platform.RuntimeOptions.Entry) || !identityASCII(platform.RuntimeOptions.Transport) || !identityASCII(platform.TunPolicy.Address) || !identityASCII(platform.TunPolicy.Route) {
		return PreparedContext{}, invalid
	}
	for _, value := range platform.PlatformPolicy.ApplicationIDs {
		if !identityASCII(value) {
			return PreparedContext{}, invalid
		}
	}
	for _, value := range platform.TunPolicy.DNSServers {
		if !identityASCII(value) {
			return PreparedContext{}, invalid
		}
	}
	if platform.TunPolicy.IPv6 != nil && (!identityASCII(platform.TunPolicy.IPv6.Address) || !identityASCII(platform.TunPolicy.IPv6.Route)) {
		return PreparedContext{}, invalid
	}
	manifest, err := CanonicalJSON(map[string]any{"schemaVersion": Version, "plannerVersion": PlannerVersion, "inputDigest": inputDigest, "resources": resources})
	if err != nil {
		return PreparedContext{}, invalid
	}
	prefs, err := CanonicalJSON(map[string]any{"inputDigest": inputDigest, "groupPreferences": preferences})
	if err != nil {
		return PreparedContext{}, invalid
	}
	prepared := PreparedContext{SchemaVersion: Version, InputDigest: inputDigest, PlannerVersion: PlannerVersion, Resources: resources, Platform: platform, GroupPreferences: preferences,
		ResourceManifestDigest: Digest(manifest), PlatformPolicyDigest: Digest(encodedPlatform), GroupPreferencesDigest: Digest(prefs)}
	identity, err := CanonicalJSON(map[string]any{"inputDigest": inputDigest, "resourceManifestDigest": prepared.ResourceManifestDigest, "platformPolicyDigest": prepared.PlatformPolicyDigest, "groupPreferencesDigest": prepared.GroupPreferencesDigest})
	if err != nil {
		return PreparedContext{}, invalid
	}
	prepared.CandidateDigest = Digest(identity)
	return prepared, nil
}
