//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy/contract"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

const domainRuleProviderContent = "payload:\n - DOMAIN-SUFFIX,proxy-fixture.test\n"

// Describing the fixed resource is pure: reopen must not rewrite or pre-open it.
func domainRuleProviderResource(requirement contract.Requirement) contract.Resource {
	content := []byte(domainRuleProviderContent)
	digest := contract.Digest(content)
	return contract.Resource{RefID: requirement.RefID, Kind: requirement.Kind, Format: requirement.Format, SourceDigest: requirement.SourceDigest,
		ContentDigest: digest, ByteLength: int64(len(content)), RelativePath: "immutable/" + digest[7:] + "/rule-provider.yaml"}
}

// Callers choose when to seed the resource; the reopen branch never calls this.
func writeDomainRuleProvider(t *testing.T, root string, resource contract.Resource) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(resource.RelativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(domainRuleProviderContent), 0600); err != nil {
		t.Fatal(err)
	}
}

func sealDomainPolicyRequest(t *testing.T, encoded []byte, inputDigest string, resource contract.Resource, preferences []contract.Preference) (R.StartRequest, contract.PreparedContext) {
	t.Helper()
	var request R.StartRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	prepared, err := contract.Seal(inputDigest, []contract.Resource{resource}, request.PreparedPolicy.Platform, preferences)
	if err != nil {
		t.Fatal(err)
	}
	request.PreparedPolicy = &prepared
	return request, prepared
}
