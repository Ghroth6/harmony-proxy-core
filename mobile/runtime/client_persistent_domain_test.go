//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyowner "github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
	D "github.com/miekg/dns"
)

const persistentDomainPassword = "fresh-process-domain-fixture-only"
const persistentDomainSeedHost = "seed.proxy-fixture.test"
const persistentDomainFreshHost = "reopened.proxy-fixture.test"
const persistentDomainReply = "fresh-process-authenticated-domain-response"

type persistentDomainResult struct {
	ProcessID              int    `json:"processId"`
	CoreInstance           string `json:"coreInstance"`
	Generation             uint64 `json:"generation"`
	InputDigest            string `json:"inputDigest"`
	CandidateDigest        string `json:"candidateDigest"`
	ResourceManifestDigest string `json:"resourceManifestDigest"`
	GroupPreferencesDigest string `json:"groupPreferencesDigest"`
	SourceInput            string `json:"sourceInput"`
	SeedIP                 string `json:"seedIP"`
	FreshIP                string `json:"freshIP"`
	DNSQuestions           uint64 `json:"dnsQuestions"`
	ResourceCountBefore    string `json:"resourceCountBefore"`
	ResourceCountAfter     string `json:"resourceCountAfter"`
	Cleanup                string `json:"cleanup"`
}

// Unlike the older MATCH/REJECT-only persistence test, this keeps a complete
// source-policy rule provider and an explicit non-default group member. The
// parent owns only independent loopback peers; each child owns a real engine,
// gVisor TUN stack, policy root and process-local coreInstance. The declared
// store-fake-ip:true is a controlled fixture, not the user's original policy.
func TestClientPersistentFakeIPFreshProcessesForwardOriginalDomainRulesAndStop(t *testing.T) {
	mode := os.Getenv("MIHOMO_D1_REOPEN_MODE")
	if mode != "" {
		runPersistentDomainChild(t, mode, os.Getenv("MIHOMO_D1_REOPEN_ROOT"))
		return
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var lock sync.Mutex
	var connections []net.Conn
	verified, closed := make(chan error, 3), make(chan error, 3)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for _, host := range []string{persistentDomainSeedHost, persistentDomainSeedHost, persistentDomainFreshHost} {
			host := host // This repository retains go1.20 range semantics.
			connection, err := listener.Accept()
			if err != nil {
				verified <- err
				return
			}
			lock.Lock()
			connections = append(connections, connection)
			lock.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				err := clientSSStreamExchange(t, connection, persistentDomainPassword, host, "request:"+host, persistentDomainReply)
				verified <- err
				if err == nil {
					_, err = connection.Read(make([]byte, 1))
				}
				closed <- err
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		lock.Lock()
		for _, connection := range connections {
			connection.Close()
		}
		lock.Unlock()
		workers.Wait()
	})
	root := t.TempDir()
	input := []byte(fmt.Sprintf(`ipv6: false
profile: {store-selected: true, store-fake-ip: true}
dns:
 enable: true
 ipv6: false
 enhanced-mode: fake-ip
 fake-ip-range: 198.18.0.1/16
 use-hosts: false
 nameserver: ['127.0.0.1:9']
 fallback-filter: {geoip: false}
proxies:
 - {name: unused-original-node, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: unused-fixture}
 - {name: saved-domain-node, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: %s}
proxy-groups:
 - {name: original-domain-select, type: select, proxies: [unused-original-node, saved-domain-node]}
 - {name: unused-original-group, type: select, proxies: [DIRECT, REJECT]}
rule-providers:
 D1Routes: {type: file, behavior: classical, format: yaml, path: './original-routes.yaml'}
rules:
 - DOMAIN-SUFFIX,direct-fixture.test,DIRECT
 - RULE-SET,D1Routes,original-domain-select
 - MATCH,REJECT
`, listener.Addr().(*net.TCPAddr).Port, persistentDomainPassword))
	if err = os.WriteFile(filepath.Join(root, "source.yaml"), input, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "policy-root"), 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var first, second persistentDomainResult
	for index, phase := range []string{"seed", "reopen"} {
		child := exec.Command(executable, "-test.run=^TestClientPersistentFakeIPFreshProcessesForwardOriginalDomainRulesAndStop$", "-test.timeout=20s")
		child.Env = append(os.Environ(), "MIHOMO_D1_REOPEN_MODE="+phase, "MIHOMO_D1_REOPEN_ROOT="+root, "MIHOMO_D1_REOPEN_SEED_IP="+first.SeedIP)
		output, err := child.CombinedOutput() // Wait reaps the old process before reopening.
		if err != nil {
			t.Fatalf("actual source-policy child %s failed: %v\n%s", phase, err, output)
		}
		var result persistentDomainResult
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "PERSISTENT_DOMAIN:") {
				if err = json.Unmarshal([]byte(strings.TrimPrefix(line, "PERSISTENT_DOMAIN:")), &result); err != nil {
					t.Fatal(err)
				}
				found = true
			}
		}
		if !found || result.ProcessID == os.Getpid() || result.ProcessID != child.Process.Pid || result.ResourceCountBefore != "0" || result.ResourceCountAfter != "0" || result.Cleanup != "complete" {
			t.Fatalf("fresh actual process omitted its own identity, known resource epoch or normal stop: %s", output)
		}
		for attempt := 0; attempt < index+1; attempt++ {
			select {
			case err := <-verified:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("actual independent peer did not authenticate the selected source node and domain bytes")
			}
			select {
			case err := <-closed:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("child normal Stop did not physically close its real encrypted connection: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("old child's real physical socket survived normal stop")
			}
		}
		if index == 0 {
			first = result
		} else {
			second = result
		}
		t.Logf("actual %s OS process: %s", phase, output)
	}
	parentInstance := instanceFromReceipt(t, R.NewManager(newDescriptors()).Query(1, 1))
	if first.ProcessID == second.ProcessID || first.CoreInstance == second.CoreInstance || first.CoreInstance == parentInstance || second.CoreInstance == parentInstance {
		t.Fatal("new actual core process inherited another process's coreInstance")
	}
	if first.SourceInput != string(input) || second.SourceInput != string(input) || first.InputDigest != contract.Digest(input) || first.InputDigest != second.InputDigest || first.CandidateDigest != second.CandidateDigest ||
		first.ResourceManifestDigest != second.ResourceManifestDigest || first.GroupPreferencesDigest != second.GroupPreferencesDigest ||
		first.SeedIP != second.SeedIP || first.DNSQuestions != 1 || second.DNSQuestions != 1 || second.FreshIP == first.SeedIP || second.FreshIP == "" {
		t.Fatalf("fresh process lost original input/resources/preferences, restored mapping or fresh-domain semantics: first=%+v second=%+v", first, second)
	}
}

func runPersistentDomainChild(t *testing.T, mode, root string) {
	t.Helper()
	if mode != "seed" && mode != "reopen" {
		t.Fatal("unexpected persistent-domain child mode")
	}
	input, err := os.ReadFile(filepath.Join(root, "source.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	policyRoot := filepath.Join(root, "policy-root")
	owner, err := policyowner.NewEngine(policyRoot)
	if err != nil {
		t.Fatal(err)
	}
	generation := nextGeneration()
	var protects atomic.Int32
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	plan := owner.Plan(mode+"-source-plan", input, nil)
	if plan.Category != "planned" || plan.ResourcesComplete || len(plan.Requirements) != 1 || len(plan.Groups) != 2 || len(plan.Groups[0].Members) != 2 || !plan.StoreFakeIP || !plan.StoreSelected {
		t.Fatalf("fresh process did not plan the complete declared saved policy: %+v", plan)
	}
	content := []byte("payload:\n - DOMAIN-SUFFIX,proxy-fixture.test\n")
	contentDigest := contract.Digest(content)
	requirement := plan.Requirements[0]
	resource := contract.Resource{RefID: requirement.RefID, Kind: requirement.Kind, Format: requirement.Format, SourceDigest: requirement.SourceDigest,
		ContentDigest: contentDigest, ByteLength: int64(len(content)), RelativePath: "immutable/" + contentDigest[7:] + "/rule-provider.yaml"}
	if mode == "seed" {
		path := filepath.Join(policyRoot, filepath.FromSlash(resource.RelativePath))
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var request R.StartRequest
	if err = json.Unmarshal(clientPolicyRequest(t, input, generation, networkGeneration, true, false), &request); err != nil {
		t.Fatal(err)
	}
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, request.PreparedPolicy.Platform,
		[]contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}})
	if err != nil {
		t.Fatal(err)
	}
	validated := owner.Validate(mode+"-fresh-validation", input, prepared)
	if validated.Category != "pass" || validated.CandidateDigest != prepared.CandidateDigest {
		t.Fatalf("new actual process failed its own full saved-policy validation: %+v", validated)
	}
	request.PreparedPolicy = &prepared
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	countBefore := owner.ResourceAcquireCount()
	started := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
	if started.Outcome != "running" || !started.ForwardingActive || started.InputDigest != contract.Digest(input) || started.CandidateDigest != prepared.CandidateDigest ||
		started.ResourceManifestDigest != prepared.ResourceManifestDigest || started.GroupPreferencesDigest != prepared.GroupPreferencesDigest || countBefore != "0" || protects.Load() != 0 {
		t.Fatalf("new actual process failed to activate exactly the newly checked saved context without acquisition: %+v", started)
	}
	initial := domainWire(t, started)
	if initial.DNS == nil || initial.DNS.Sequence != 0 || initial.DNS.Dropped != 0 || initial.DNS.Saturated || len(initial.DNS.Queries) != 0 || len(initial.Connections) != 0 {
		t.Fatal("fresh actual process inherited old runtime observations")
	}
	seedIP := net.ParseIP(os.Getenv("MIHOMO_D1_REOPEN_SEED_IP"))
	freshIP := ""
	if mode == "reopen" {
		if seedIP == nil {
			t.Fatal("missing independently observed old fake-IP")
		}
		// No current-process question has been sent. This TCP flow must use the
		// restored mapper, and must honestly report no current DNS sequence.
		domainTCPExchange(t, system, seedIP, 443, 55101, "request:"+persistentDomainSeedHost, persistentDomainReply)
		observed := domainWire(t, manager.Query(generation, 1))
		if observed.DNS.Sequence != 0 || len(observed.Connections) != 1 || observed.Connections[0].Attribution == nil ||
			observed.Connections[0].Attribution.DomainDigest != domainHash(persistentDomainSeedHost) || observed.Connections[0].Attribution.DNSSequence != 0 {
			t.Fatal("restored mapper was not usable before any new question, or invented a current-process DNS link")
		}
	}
	host := persistentDomainSeedHost
	if mode == "reopen" {
		host = persistentDomainFreshHost
	}
	answer := clientDomainQuestion(t, system, host+".", D.TypeA, 55001)
	if answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatal("fresh actual TUN question did not return its declared fake-IP answer")
	}
	address := answer.Answer[0].(*D.A).A
	if mode == "seed" {
		seedIP = address
	} else {
		freshIP = address.String()
		if freshIP == seedIP.String() {
			t.Fatal("new host overwrote the previously committed fake-IP mapping")
		}
	}
	domainTCPExchange(t, system, address, 443, 55102, "request:"+host, persistentDomainReply)
	observed := manager.Query(generation, 1)
	wire := domainWire(t, observed)
	expectedConnections := 1
	if mode == "reopen" {
		expectedConnections = 2
	}
	if len(observed.Connections) != expectedConnections || wire.DNS.Sequence != 1 || wire.DNS.Dropped != 0 || wire.DNS.Saturated || len(wire.DNS.Queries) != 1 || protects.Load() == 0 {
		t.Fatalf("current process did not report its actual domain forwarding and DNS epoch: %+v", observed)
	}
	query := wire.DNS.Queries[0]
	if query.QuestionDigest != domainHash(host) || query.Outcome != "response" || !query.FakeIP || query.AnswersTruncated || len(query.AnswerAddresses) != 1 || query.AnswerAddresses[0] != address.String() {
		t.Fatalf("fresh question and actual mapped answer were not attributable: %+v", query)
	}
	for index, connection := range observed.Connections {
		expectedHost, expectedIP, sequence := host, address.String(), uint64(1)
		if mode == "reopen" && index == 0 {
			expectedHost, expectedIP, sequence = persistentDomainSeedHost, seedIP.String(), 0
		}
		attribution := wire.Connections[index].Attribution
		if connection.TargetAddress != expectedIP || connection.Rule != "RuleSet" || connection.Node != "saved-domain-node" ||
			connection.Upload < int64(len("request:"+expectedHost)) || connection.Download < int64(len(persistentDomainReply)) || attribution == nil ||
			attribution.DomainDigest != domainHash(expectedHost) || attribution.DNSSequence != sequence || attribution.RulePayloadDigest != domainHash("D1Routes") || attribution.NodeDigest != domainHash("saved-domain-node") {
			t.Fatalf("actual saved preference, full resource rule and restored/fresh domain lost their association: %+v", connection)
		}
	}
	stopped := manager.Stop(generation)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.ForwardingActive || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("fresh process normal stop did not join its real TUN/DNS/TCP/database owners: %+v", stopped)
	}
	policyClosed := false
	for _, resource := range stopped.Resources {
		policyClosed = policyClosed || resource.Kind == "policy-services" && resource.State == "closed" && resource.CloseResult == 0
	}
	if !policyClosed || owner.Close() != nil || owner.ResourceAcquireCount() != "0" {
		t.Fatal("fresh process did not close its real policy/database root or changed its known resource counter")
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatal("fresh process normal stop did not close each owned descriptor once")
		}
	}
	for label, receipt := range map[string]R.Receipt{"RUNNING": observed, "STOPPED": stopped} {
		encoded, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("PERSISTENT_DOMAIN_%s:%s\n", label, encoded)
	}
	result := persistentDomainResult{ProcessID: os.Getpid(), CoreInstance: started.CoreInstance, Generation: generation,
		InputDigest: started.InputDigest, CandidateDigest: started.CandidateDigest, ResourceManifestDigest: started.ResourceManifestDigest,
		GroupPreferencesDigest: started.GroupPreferencesDigest, SourceInput: string(input), SeedIP: seedIP.String(), FreshIP: freshIP, DNSQuestions: wire.DNS.Sequence,
		ResourceCountBefore: countBefore, ResourceCountAfter: owner.ResourceAcquireCount(), Cleanup: stopped.Cleanup}
	output, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("PERSISTENT_DOMAIN:" + string(output))
}
