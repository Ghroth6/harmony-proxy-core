package policy_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy"
)

// The fixture was emitted by production ArkTS sealPreparedPolicy through the
// existing DevEco TypeScript host loader. Go must consume those exact bytes,
// independently reopen/build/discard a real candidate and reject altered scope.
func TestOriginalPolicyConsumesActualApplicationScopeContexts(t *testing.T) {
	var bundle struct {
		Input []byte `json:"input"`
		Cases []struct {
			Name     string          `json:"name"`
			Accepted bool            `json:"accepted"`
			Context  json.RawMessage `json:"context"`
		} `json:"cases"`
	}
	data, err := os.ReadFile("testdata/application-scope-contexts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, fixture := range bundle.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			receipt, err := engine.ValidateJSON("application-produced-context", bundle.Input, fixture.Context)
			if accepted := err == nil && receipt.Category == "pass"; accepted != fixture.Accepted {
				t.Fatalf("application/core scope disagreement: %v %s/%s", err, receipt.Category, receipt.Code)
			}
		})
	}
}
