//go:build with_gvisor && !no_tailscale

package policy_test

import (
	"github.com/metacubex/mihomo/mobile/policy"
	"testing"
)

func TestOriginalPolicyDoesNotBorrowGlobalNodeDNSRegistry(t *testing.T) {
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nproxies:\n - {name: Public, type: tailscale}\nrules: ['MATCH,Public']\n")
	plan := engine.Plan("node-global-resource-owner", input, nil)
	if plan.Category != "planned" || plan.Code != "" {
		t.Fatalf("global DNS registration requires a captured candidate owner: %s/%s", plan.Category, plan.Code)
	}
}
