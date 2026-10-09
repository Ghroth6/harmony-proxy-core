package log_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	L "github.com/metacubex/mihomo/log"
)

type mobileOutput struct {
	sync.Mutex
	events []L.MobileEvent
}

func (o *mobileOutput) WriteMobileEvent(event L.MobileEvent) {
	o.Lock()
	defer o.Unlock()
	o.events = append(o.events, event)
}
func (o *mobileOutput) take() []L.MobileEvent {
	o.Lock()
	defer o.Unlock()
	result := o.events
	o.events = nil
	return result
}

var output mobileOutput

func TestMain(m *testing.M) {
	if os.Getenv("MIHOMO_LOG_CHILD") == "" {
		L.InstallMobileOutput(&output)
	}
	os.Exit(m.Run())
}
func TestMobileFailureExposesOnlyTypedStageClassErrnoAndGeneration(t *testing.T) {
	output.take()
	private := fmt.Errorf("private-node 203.0.113.8:443 password=secret: %w", syscall.Errno(10061))
	L.MobileFailure(7, L.StageForwardDial, L.MarkMobileError(L.StagePhysicalDial, private))
	events := output.take()
	if len(events) != 1 || events[0].String() != "stage=physical-dial class=syscall errno=10061 generation=7" {
		t.Fatalf("unexpected safe event: %v", events)
	}
	if !errors.Is(L.MarkMobileError(L.StageTLS, private), syscall.Errno(10061)) {
		t.Fatal("stage decoration lost original error identity")
	}
}
func TestMobileUntypedMessagesReachNeitherStdoutNorSubscribers(t *testing.T) {
	output.take()
	sub := L.Subscribe()
	defer L.UnSubscribe(sub)
	L.Warnln("private-node %s", "password=secret")
	L.Infoln("private-target %s", "203.0.113.1")
	select {
	case event := <-sub:
		t.Fatalf("untyped event escaped: %v", event)
	case <-time.After(20 * time.Millisecond):
	}
	if len(output.take()) != 0 {
		t.Fatal("untyped payload reached mobile sink")
	}
}
func TestMobileBoundaryMapsWrappedTimeoutEOFAndUnknownWithoutErrorText(t *testing.T) {
	for _, example := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("secret: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("secret: %w", context.Canceled), "canceled"},
		{fmt.Errorf("secret: %w", io.EOF), "eof"},
		{unprintableError{}, "unknown"},
	} {
		output.take()
		L.MobileFailure(9, L.StageTLS, example.err)
		events := output.take()
		if len(events) != 1 || events[0].String() != "stage=tls-handshake class="+example.want+" errno=0 generation=9" {
			t.Fatalf("unexpected event: %v", events)
		}
	}
}

type unprintableError struct{}

func (unprintableError) Error() string { panic("error text must not be requested") }
func TestMobileSinkIsProcessOwnedAndConcurrentEventsAreComplete(t *testing.T) {
	if L.InstallMobileOutput(&mobileOutput{}) || L.InstallMobileOutput(nil) {
		t.Fatal("mobile sink was replaced")
	}
	output.take()
	var calls sync.WaitGroup
	for index := 0; index < 32; index++ {
		calls.Add(1)
		go func() { defer calls.Done(); L.MobilePhase(12, L.StageRunning) }()
	}
	calls.Wait()
	events := output.take()
	if len(events) != 32 {
		t.Fatalf("lost completed events: %d", len(events))
	}
	for _, event := range events {
		if event.String() != "stage=running class=none errno=0 generation=12" {
			t.Fatalf("corrupted event: %v", event)
		}
	}
	L.MobilePhase(0, L.StageRunning)
	L.MobilePhase(1<<32, L.StageRunning)
	L.MobilePhase(1, L.MobileStage(255))
	if len(output.take()) != 0 {
		t.Fatal("invalid stage/generation accepted")
	}
}
func TestUpstreamDaemonRetainsOriginalLogOutputAndSubscriptions(t *testing.T) {
	if os.Getenv("MIHOMO_LOG_CHILD") == "upstream" {
		original := errors.New("daemon-original-error")
		if L.MarkMobileError(L.StageTLS, original) != original {
			t.Fatal("daemon error identity changed")
		}
		sub := L.Subscribe()
		defer L.UnSubscribe(sub)
		L.Warnln("daemon original %s", "sentinel")
		if (<-sub).Payload != "daemon original sentinel" {
			t.Fatal("daemon subscription changed")
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestUpstreamDaemonRetainsOriginalLogOutputAndSubscriptions$")
	command.Env = append(os.Environ(), "MIHOMO_LOG_CHILD=upstream")
	result, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(result, []byte("daemon original sentinel")) {
		t.Fatalf("upstream output missing: %s %v", result, err)
	}
}

func TestMobileUntypedOutputDoesNotAppearOnProcessStreams(t *testing.T) {
	if os.Getenv("MIHOMO_LOG_CHILD") == "streams" {
		L.InstallMobileOutput(&output)
		L.Debugln("private-stream-secret")
		L.Infoln("private-stream-secret")
		L.Warnln("private-stream-secret")
		L.Errorln("private-stream-secret")
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestMobileUntypedOutputDoesNotAppearOnProcessStreams$")
	command.Env = append(os.Environ(), "MIHOMO_LOG_CHILD=streams")
	result, err := command.CombinedOutput()
	if err != nil || bytes.Contains(result, []byte("private-stream-secret")) {
		t.Fatalf("mobile raw process output: %q %v", result, err)
	}
}
func TestMobileFatalDoesNotExposeOriginalText(t *testing.T) {
	if os.Getenv("MIHOMO_LOG_CHILD") == "fatal" {
		L.InstallMobileOutput(&output)
		L.Fatalln("private-password-secret")
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestMobileFatalDoesNotExposeOriginalText$")
	command.Env = append(os.Environ(), "MIHOMO_LOG_CHILD=fatal")
	result, err := command.CombinedOutput()
	if err == nil || strings.Contains(string(result), "private-password-secret") {
		t.Fatalf("fatal behavior/output: %q %v", result, err)
	}
}
