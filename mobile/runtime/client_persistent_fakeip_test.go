//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

const persistentClientPolicy = `ipv6: false
profile: {store-fake-ip: true}
dns:
 enable: true
 ipv6: false
 enhanced-mode: fake-ip
 use-hosts: false
 fake-ip-range: 198.18.0.1/16
 nameserver: [192.0.2.53]
 default-nameserver: [192.0.2.53]
 fallback-filter: {geoip: false}
rules: ['MATCH,REJECT']
`

func TestClientPersistentFakeIPActualFreshProcessesAndUnknownOpenCleanup(t *testing.T) {
	mode := os.Getenv("MIHOMO_PUBLIC_STATE_MODE")
	if mode == "" {
		root := t.TempDir()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		var first string
		for _, mode := range []string{"seed", "reopen", "blocked"} {
			child := exec.Command(executable, "-test.run=^TestClientPersistentFakeIPActualFreshProcessesAndUnknownOpenCleanup$", "-test.timeout=15s")
			child.Env = append(os.Environ(), "MIHOMO_PUBLIC_STATE_MODE="+mode, "MIHOMO_PUBLIC_STATE_ROOT="+root)
			output, err := child.CombinedOutput()
			if err != nil {
				t.Fatalf("actual public state child %s failed: %v\n%s", mode, err, output)
			}
			if mode == "blocked" {
				continue
			}
			value := ""
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "PUBLIC_FAKEIP:") {
					value = strings.TrimSpace(strings.TrimPrefix(line, "PUBLIC_FAKEIP:"))
				}
			}
			if value == "" || (first != "" && first != value) {
				t.Fatal("fresh actual core processes must reopen the same original fake-IP mapping")
			}
			first = value
		}
		return
	}
	rootPath := os.Getenv("MIHOMO_PUBLIC_STATE_ROOT")
	input := []byte(persistentClientPolicy)
	if mode == "blocked" {
		// A real independently owned DB holds the actual file lock. bbolt's
		// failed-open cleanup result is unobservable; the candidate must retain
		// that uncertainty and its root instead of reporting clean. The child
		// process exits only after this negative ownership evidence is read back.
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		locked, err := fakeip.NewScopedPersistence(root, contract.Digest(input))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Persistence: true, ScopedPersistence: locked}); err != nil {
			t.Fatal(err)
		}
		if err = locked.Activate(); err != nil {
			t.Fatal(err)
		}
		defer locked.Close()
	}
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	owner, err := policyowner.NewEngine(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	request := clientPolicyRequest(t, input, generation, networkGeneration, true, false)
	started := manager.Start(manager.Consume(generation, 1, 9), input, request)
	if mode == "blocked" {
		stopped := manager.Stop(generation)
		if started.Outcome != "running" || !started.ForwardingActive || stopped.Cleanup != "unknown" || stopped.Outcome != "failed" {
			t.Fatalf("cache open failure must allow runtime admission while actual unknown cleanup remains reported: start=%+v stop=%+v", started, stopped)
		}
		unknown := false
		for _, resource := range stopped.Resources {
			unknown = unknown || (resource.Kind == "policy-services" && resource.State == "unknown")
		}
		var target R.StartRequest
		if err = json.Unmarshal(request, &target); err != nil {
			t.Fatal(err)
		}
		if !unknown || owner.Close() == nil || owner.Validate("state-failure-recheck", input, *target.PreparedPolicy).Category == "pass" {
			t.Fatal("failed actual store cleanup must retain the session/root and prevent another candidate")
		}
		if protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
			t.Fatal("failed state activation must not dial DNS or acquire resources")
		}
		return
	}
	if started.Outcome != "running" || !started.ForwardingActive || owner.Close() == nil {
		t.Fatalf("persistent original-policy runtime must activate and pin its trusted root: %+v", started)
	}
	message := new(D.Msg).SetQuestion("documentation-persistent.example.", D.TypeA)
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 51711, payload))
	select {
	case packet := <-system.output:
		answer := new(D.Msg)
		if len(packet) < 28 || answer.Unpack(packet[28:]) != nil || len(answer.Answer) != 1 || answer.Rcode != D.RcodeSuccess {
			t.Fatal("actual TUN DNS must return a committed scoped fake-IP answer")
		}
		fmt.Println("PUBLIC_FAKEIP:" + answer.Answer[0].(*D.A).A.String())
	case <-time.After(time.Second):
		t.Fatal("actual persistent fake-IP TUN request did not return")
	}
	if protects.Load() != 0 || owner.ResourceAcquireCount() != "0" {
		t.Fatal("persistent fake-IP start/lookup must require no network")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("actual persistent DNS/DB stop must join and close: %+v", stopped)
	}
	closed := false
	for _, resource := range stopped.Resources {
		closed = closed || (resource.Kind == "policy-services" && resource.State == "closed" && resource.CloseResult == 0)
	}
	if !closed || owner.Close() != nil {
		t.Fatal("actual DB closure must release the policy session and trusted root")
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("normal persistent runtime stop must close each owned descriptor exactly once")
		}
	}
}
