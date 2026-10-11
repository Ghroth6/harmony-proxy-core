package runtime_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	R "github.com/metacubex/mihomo/mobile/runtime"
)

func instanceFromReceipt(t *testing.T, receipt R.Receipt) string {
	t.Helper()
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		CoreInstance string `json:"coreInstance"`
	}
	if err = json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^core-[0-9a-f]{32}$`).MatchString(value.CoreInstance) {
		t.Fatalf("actual runtime receipt omitted its process identity: %q", value.CoreInstance)
	}
	return value.CoreInstance
}

func TestCoreRuntimeProcessIdentityIsSharedByActualReceipts(t *testing.T) {
	first := R.NewManager(newDescriptors())
	second := R.NewManager(newDescriptors())
	identity := instanceFromReceipt(t, first.Query(1, 1))
	if instanceFromReceipt(t, second.Query(2, 2)) != identity {
		t.Fatal("managers in one actual core process received different instance identities")
	}
	rejected := second.Start(second.Consume(2, 7, 9), sample, []byte("{}"))
	if instanceFromReceipt(t, rejected) != identity || instanceFromReceipt(t, second.Stop(2)) != identity {
		t.Fatal("rejected or stopped receipts changed the actual core process identity")
	}
}

func TestCoreRuntimeFreshProcessIdentity(t *testing.T) {
	if os.Getenv("MIHOMO_RUNTIME_INSTANCE_FIXTURE") == "1" {
		fmt.Println("CORE_INSTANCE:" + instanceFromReceipt(t, R.NewManager(newDescriptors()).Query(1, 1)))
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	read := func() string {
		child := exec.Command(executable, "-test.run=^TestCoreRuntimeFreshProcessIdentity$")
		child.Env = append(os.Environ(), "MIHOMO_RUNTIME_INSTANCE_FIXTURE=1")
		payload, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("fresh actual Go process failed: %v\n%s", err, payload)
		}
		for _, line := range strings.Split(string(payload), "\n") {
			if strings.HasPrefix(line, "CORE_INSTANCE:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "CORE_INSTANCE:"))
			}
		}
		t.Fatalf("fresh actual Go process omitted the runtime instance receipt: %s", payload)
		return ""
	}
	first, second := read(), read()
	if first == second || first == instanceFromReceipt(t, R.NewManager(newDescriptors()).Query(1, 1)) {
		t.Fatal("fresh actual core processes reused an earlier process identity")
	}
}
