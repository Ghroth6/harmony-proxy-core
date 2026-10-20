//go:build with_gvisor

package runtime_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

// Each peer records real DNS wire questions, then returns its declared result.
// No host resolver, network settings or process-global resolver is replaced.
type dnsFailurePeer struct {
	listener  net.Listener
	done      chan struct{}
	mu        sync.Mutex
	questions []D.Question
	errors    []error
}

func newDNSFailurePeer(t *testing.T, rcode int) *dnsFailurePeer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &dnsFailurePeer{listener: listener, done: make(chan struct{})}
	go func() {
		defer close(peer.done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				wire := &D.Conn{Conn: connection}
				question, err := wire.ReadMsg()
				if err == nil && len(question.Question) != 1 {
					err = errors.New("DNS peer expected exactly one wire question")
				}
				peer.mu.Lock()
				if err == nil {
					peer.questions = append(peer.questions, question.Question[0])
				} else {
					peer.errors = append(peer.errors, err)
				}
				peer.mu.Unlock()
				if err != nil {
					return
				}
				answer := new(D.Msg).SetRcode(question, rcode)
				if rcode == D.RcodeSuccess {
					answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 17)}}
				}
				if err := wire.WriteMsg(answer); err != nil {
					peer.mu.Lock()
					peer.errors = append(peer.errors, err)
					peer.mu.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-peer.done })
	return peer
}

func (p *dnsFailurePeer) assertQuestions(t *testing.T, hosts ...string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.errors) != 0 || (len(hosts) == 0) != (len(p.questions) == 0) {
		t.Fatalf("declared physical DNS peer questions/errors differ: questions=%+v errors=%v", p.questions, p.errors)
	}
	seen := make(map[string]bool)
	for _, question := range p.questions {
		allowed := false
		for _, host := range hosts {
			allowed = allowed || question.Name == host+"."
		}
		if !allowed || question.Qtype != D.TypeA || question.Qclass != D.ClassINET {
			t.Fatalf("declared physical DNS peer received another question: %+v", question)
		}
		seen[question.Name] = true
	}
	for _, host := range hosts {
		if !seen[host+"."] {
			t.Fatalf("declared physical DNS peer did not receive %s", host)
		}
	}
	t.Logf("declared DNS peer wire questions: %+v", p.questions)
}

// The diagnostic differs from the valid complete source only in its explicitly
// declared main/fallback peers. Groups, original resource, rules and preferences
// stay present; this is never a selected-node MATCH candidate.
func dnsFailureSource(main, fallback string, proxyPort int) []byte {
	return []byte(fmt.Sprintf(`ipv6: false
profile: {store-selected: true}
dns:
 enable: true
 ipv6: false
 enhanced-mode: redir-host
 use-hosts: false
 default-nameserver: [127.0.0.1:9]
 nameserver: ['tcp://%s']
 fallback: ['tcp://%s']
 fallback-lazy-query: true
 fallback-filter: {geoip: false}
proxies:
 - {name: unused-original-node, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: unused-fixture}
 - {name: original-selected-node, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: dns-fixture-only}
proxy-groups:
 - {name: original-domain-select, type: select, proxies: [unused-original-node, original-selected-node]}
 - {name: unused-original-group, type: select, proxies: [DIRECT, REJECT]}
rule-providers:
 D1Routes: {type: file, behavior: classical, format: yaml, path: './original-routes.yaml'}
rules:
 - DOMAIN-SUFFIX,direct-fixture.test,DIRECT
 - RULE-SET,D1Routes,original-domain-select
 - MATCH,REJECT
`, main, fallback, proxyPort))
}

type dnsFailureRun struct {
	manager    *R.Manager
	system     *packetDescriptors
	owner      *policyowner.Engine
	generation uint64
	protects   *atomic.Int32
	started    R.Receipt
}

func startDNSFailureSource(t *testing.T, input []byte) dnsFailureRun {
	t.Helper()
	root := t.TempDir()
	owner, err := policyowner.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	generation := nextGeneration()
	protects := new(atomic.Int32)
	register(generation, func(uint64, uint64, uintptr) int32 { protects.Add(1); return protection.Success })
	system := newPacketDescriptors()
	manager := R.NewManagerWithPolicy(system, &productionGate, owner)
	t.Cleanup(func() { manager.Stop(generation); owner.Close() })
	networkGeneration := publishClientNetwork(t, manager, "192.0.2.53")
	plan := owner.Plan("dns-complete-source", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 || len(plan.Groups) != 2 {
		t.Fatalf("full DNS source lost original resources/groups: %+v", plan)
	}
	content := []byte("payload:\n - DOMAIN-SUFFIX,proxy-fixture.test\n")
	requirement := plan.Requirements[0]
	contentDigest := contract.Digest(content)
	resource := contract.Resource{RefID: requirement.RefID, Kind: requirement.Kind, Format: requirement.Format, SourceDigest: requirement.SourceDigest, ContentDigest: contentDigest, ByteLength: int64(len(content)), RelativePath: "immutable/" + contentDigest[7:] + "/rule-provider.yaml"}
	path := filepath.Join(root, filepath.FromSlash(resource.RelativePath))
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	var request R.StartRequest
	if err = json.Unmarshal(clientPolicyRequest(t, input, generation, networkGeneration, true, false), &request); err != nil {
		t.Fatal(err)
	}
	preferences := []contract.Preference{{GroupRef: plan.Groups[0].GroupRef, MemberRef: plan.Groups[0].Members[1].MemberRef}}
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, request.PreparedPolicy.Platform, preferences)
	if err != nil {
		t.Fatal(err)
	}
	request.OperationID = fmt.Sprintf("dns-policy-%d", generation)
	request.PreparedPolicy = &prepared
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	started := manager.Start(manager.Consume(generation, 1, 9), input, encoded)
	if started.Outcome != "running" || !started.ForwardingActive || started.InputDigest != contract.Digest(input) || started.CandidateDigest != prepared.CandidateDigest || started.ResourceManifestDigest != prepared.ResourceManifestDigest || started.GroupPreferencesDigest != prepared.GroupPreferencesDigest {
		t.Fatalf("actual complete DNS source did not activate its accepted identity: %+v", started)
	}
	return dnsFailureRun{manager, system, owner, generation, protects, started}
}

func (r dnsFailureRun) stop(t *testing.T) R.Receipt {
	t.Helper()
	stopped := r.manager.Stop(r.generation)
	if stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.ForwardingActive || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("normal DNS source stop did not join actual owners: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if r.system.closes[fd] != 1 {
			t.Fatalf("DNS source descriptor %d did not close exactly once", fd)
		}
	}
	if r.owner.ResourceAcquireCount() != "0" {
		t.Fatal("DNS/stop silently acquired a policy resource")
	}
	if err := r.owner.Close(); err != nil {
		t.Fatal(err)
	}
	return stopped
}

func TestClientTUNDNSTerminalFailurePreservesFallbackAndRecoversOriginalSource(t *testing.T) {
	mainFailure := newDNSFailurePeer(t, D.RcodeServerFailure)
	fallbackFailure := newDNSFailurePeer(t, D.RcodeServerFailure)
	valid := newDNSFailurePeer(t, D.RcodeSuccess)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	original := dnsFailureSource(valid.listener.Addr().String(), valid.listener.Addr().String(), target.Addr().(*net.TCPAddr).Port)
	diagnostic := dnsFailureSource(mainFailure.listener.Addr().String(), fallbackFailure.listener.Addr().String(), target.Addr().(*net.TCPAddr).Port)
	if contract.Digest(original) == contract.Digest(diagnostic) {
		t.Fatal("diagnostic source must have an independent original identity")
	}
	const failedHost = "terminal.direct-fixture.test"
	failed := startDNSFailureSource(t, diagnostic)
	question := new(D.Msg).SetQuestion(failedHost+".", D.TypeA)
	question.Id = 54601
	payload, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	failed.system.inject(clientUDP4Packet(&net.UDPAddr{IP: net.IPv4(10, 111, 0, 2), Port: 53}, 54601, payload))
	var observed R.Receipt
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		observed = failed.manager.Query(failed.generation, 1)
		if observed.DNS != nil && observed.DNS.Sequence == 1 && observed.PendingOwners.DNSWaiters == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if observed.DNS == nil || observed.DNS.Sequence != 1 || len(observed.DNS.Queries) != 1 {
		t.Fatalf("actual captured DNS terminal result was unavailable: %+v", observed)
	}
	result := observed.DNS.Queries[0]
	if result.QuestionDigest != domainHash(failedHost) || result.QueryType != D.TypeA || result.Transport != "udp" || result.Outcome != "error" || result.FailureCode != "DNS_SERVICE_ERROR" || result.Rcode != -1 || len(result.AnswerAddresses) != 0 || result.FakeIP {
		t.Fatalf("actual aggregate service error became another DNS result: %+v", result)
	}
	mainFailure.assertQuestions(t, failedHost)
	fallbackFailure.assertQuestions(t, failedHost)
	valid.assertQuestions(t)
	if observed.Outcome != "running" || observed.Phase != "running" || !observed.ForwardingActive || observed.FailureCode != "" || len(observed.Connections) != 0 || failed.protects.Load() == 0 {
		t.Fatalf("single DNS failure changed lifecycle, bypassed declared peers or routed a target: %+v", observed)
	}
	select {
	case <-failed.system.output:
		t.Fatal("strict captured relay synthesized a client answer after an actual service error")
	case <-time.After(20 * time.Millisecond):
	}
	stopped := failed.stop(t)
	if stopped.DNS == nil || stopped.DNS.Queries[0].FailureCode != "DNS_SERVICE_ERROR" {
		t.Fatal("normal stop erased the attributable failed DNS history")
	}
	if receipt, err := json.Marshal(observed); err == nil {
		t.Logf("D1_DNS_FAILURE_RECEIPT:%s", receipt)
	}
	// User recovery selects the untouched valid source after a complete stop;
	// the new run generation must resolve a different, previously unused hostname.
	const recoveredHost = "recovered.proxy-fixture.test"
	const requestBytes = "recovered-original-request"
	const responseBytes = "fresh-restored-target-response"
	verified, closed := make(chan error, 1), make(chan error, 1)
	targetDone, targetConnection := make(chan struct{}), make(chan net.Conn, 1)
	go func() {
		defer close(targetDone)
		connection, err := target.Accept()
		if err != nil {
			verified <- err
			return
		}
		targetConnection <- connection
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		err = clientSSStreamExchange(t, connection, "dns-fixture-only", recoveredHost, requestBytes, responseBytes)
		verified <- err
		if err == nil {
			_, err = connection.Read(make([]byte, 1))
			closed <- err
		}
	}()
	t.Cleanup(func() {
		target.Close()
		select {
		case connection := <-targetConnection:
			connection.Close()
		default:
		}
		<-targetDone
	})
	recovered := startDNSFailureSource(t, original)
	answer := clientDomainQuestion(t, recovered.system, recoveredHost+".", D.TypeA, 54602)
	if answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "203.0.113.17" {
		t.Fatal("restored complete original source did not return its actual DNS answer")
	}
	domainTCPExchange(t, recovered.system, answer.Answer[0].(*D.A).A, 443, 54603, requestBytes, responseBytes)
	if err = <-verified; err != nil {
		t.Fatal(err)
	}
	receipt := recovered.manager.Query(recovered.generation, 1)
	if receipt.CoreInstance != observed.CoreInstance || receipt.Generation == observed.Generation || receipt.OperationID == observed.OperationID || receipt.InputDigest != contract.Digest(original) || receipt.DNS == nil || receipt.DNS.Sequence != 1 || receipt.DNS.Queries[0].QuestionDigest != domainHash(recoveredHost) || receipt.DNS.Queries[0].Outcome != "response" {
		t.Fatalf("recovery reused failed epoch/results or changed original source identity: %+v", receipt)
	}
	valid.assertQuestions(t, recoveredHost)
	mainFailure.assertQuestions(t, failedHost)
	fallbackFailure.assertQuestions(t, failedHost)
	if len(receipt.Connections) != 1 || receipt.Connections[0].Rule != "RuleSet" || receipt.Connections[0].Node != "original-selected-node" || receipt.Connections[0].Upload == 0 || receipt.Connections[0].Download == 0 || receipt.Connections[0].Attribution == nil || receipt.Connections[0].Attribution.DomainDigest != domainHash(recoveredHost) || receipt.Connections[0].Attribution.DNSSequence != 1 {
		t.Fatalf("restored source did not return fresh bytes through its original resource rule/selected preference: %+v", receipt)
	}
	recovered.stop(t)
	select {
	case err = <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("normal recovery stop did not physically close target: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal recovery stop left a real target connection open")
	}
	if encoded, err := json.Marshal(receipt); err == nil {
		t.Logf("D1_DNS_RECOVERY_RECEIPT:%s", encoded)
	}
}

func TestClientTUNDNSOriginalAllowedFallbackCanStillSucceed(t *testing.T) {
	mainFailure := newDNSFailurePeer(t, D.RcodeServerFailure)
	fallback := newDNSFailurePeer(t, D.RcodeSuccess)
	input := dnsFailureSource(mainFailure.listener.Addr().String(), fallback.listener.Addr().String(), 9)
	run := startDNSFailureSource(t, input)
	const host = "allowed-fallback.direct-fixture.test"
	answer := clientDomainQuestion(t, run.system, host+".", D.TypeA, 54611)
	if answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "203.0.113.17" {
		t.Fatal("configured main failure suppressed its original allowed fallback answer")
	}
	mainFailure.assertQuestions(t, host)
	fallback.assertQuestions(t, host)
	observed := run.manager.Query(run.generation, 1)
	if observed.DNS == nil || len(observed.DNS.Queries) != 1 || observed.DNS.Queries[0].Outcome != "response" || observed.DNS.Queries[0].Rcode != D.RcodeSuccess || observed.DNS.Queries[0].FailureCode != "" || observed.DNS.Queries[0].QuestionDigest != domainHash(host) || observed.DNS.Queries[0].FakeIP || observed.Phase != "running" || !observed.ForwardingActive || len(observed.Connections) != 0 || run.protects.Load() == 0 {
		t.Fatalf("allowed fallback result changed service identity/state or implied a target connection: %+v", observed)
	}
	run.stop(t)
	if encoded, err := json.Marshal(observed); err == nil {
		t.Logf("D1_DNS_ALLOWED_FALLBACK_RECEIPT:%s", encoded)
	}
}
