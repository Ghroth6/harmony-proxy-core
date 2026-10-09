//go:build with_gvisor

package runtime_test

import (
	"context"
	L "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/mobile/protection"
	"sync"
	"testing"
	"time"
)

type runtimeLogOutput struct {
	sync.Mutex
	events  []L.MobileEvent
	changed chan struct{}
}

func (o *runtimeLogOutput) WriteMobileEvent(event L.MobileEvent) {
	o.Lock()
	o.events = append(o.events, event)
	o.Unlock()
	select {
	case o.changed <- struct{}{}:
	default:
	}
}

var runtimeLogs = runtimeLogOutput{changed: make(chan struct{}, 1)}
var installRuntimeLogs sync.Once

func (o *runtimeLogOutput) wait(generation uint64, stage L.MobileStage, class L.MobileClass) bool {
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		o.Lock()
		found := false
		for _, event := range o.events {
			if event.Generation == generation && event.Stage == stage && event.Class == class {
				found = true
				break
			}
		}
		o.Unlock()
		if found {
			return true
		}
		select {
		case <-o.changed:
		case <-deadline.C:
			return false
		}
	}
}
func TestRealTLSFailureAndJoinedStopEmitOnlySafeGenerationFacts(t *testing.T) {
	installRuntimeLogs.Do(func() {
		if !L.InstallMobileOutput(&runtimeLogs) {
			t.Fatal("mobile output already installed")
		}
	})
	peer := newTrojanPeer(t, "wrong-name")
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	if !runtimeLogs.wait(generation, L.StageTLS, L.ClassCertName) {
		t.Fatal("actual TLS hostname failure had no typed correlated event")
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarding not joined")
	}
	if !runtimeLogs.wait(generation, L.StageRunning, L.ClassNone) || !runtimeLogs.wait(generation, L.StageStopped, L.ClassNone) {
		t.Fatal("actual running/cleanup phases were not observed")
	}
}

func TestRealPeerEOFKeepsTLSStageWithoutClaimingCertificateFailure(t *testing.T) {
	installRuntimeLogs.Do(func() {
		if !L.InstallMobileOutput(&runtimeLogs) {
			t.Fatal("mobile output already installed")
		}
	})
	peer := newTrojanPeer(t, "eof")
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	if !runtimeLogs.wait(generation, L.StageTLS, L.ClassEOF) {
		t.Fatal("peer EOF not classified at actual TLS operation")
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed TLS entry not joined")
	}
	if peer.accepted.Load() < 1 || len(manager.Query(generation, 1).Connections) != 0 {
		t.Fatal("incomplete TLS exchange published successful forwarding")
	}
}

func TestRealProtectionFailureIsCorrelatedWithoutPhysicalConnection(t *testing.T) {
	installRuntimeLogs.Do(func() {
		if !L.InstallMobileOutput(&runtimeLogs) {
			t.Fatal("mobile output already installed")
		}
	})
	peer := newTrojanPeer(t, "valid")
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.PlatformFailure })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	if !runtimeLogs.wait(generation, L.StageProtect, L.ClassProtection) {
		t.Fatal("actual protection failure lost its typed stage")
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed protection entry not joined")
	}
	if peer.accepted.Load() != 0 {
		t.Fatal("protected failure physically connected")
	}
}

func TestActualTrojanTLSRecordFailureExposesNoPeerPayload(t *testing.T) {
	installRuntimeLogs.Do(func() {
		if !L.InstallMobileOutput(&runtimeLogs) {
			t.Fatal("mobile output already installed")
		}
	})
	peer := newTrojanPeer(t, "record")
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	if !runtimeLogs.wait(generation, L.StageTLS, L.ClassTLSRecord) {
		t.Fatal("actual Trojan TLS record failure was not classified")
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invalid TLS record entry not joined")
	}
}

func TestRealPhysicalDialFailurePreservesObservedErrno(t *testing.T) {
	installRuntimeLogs.Do(func() {
		if !L.InstallMobileOutput(&runtimeLogs) {
			t.Fatal("mobile output already installed")
		}
	})
	peer := newTrojanPeer(t, "valid")
	if err := peer.listener.Close(); err != nil {
		t.Fatal(err)
	}
	manager, generation, system := startTrojanRun(t, peer, func(uint64, uint64, uintptr) int32 { return protection.Success })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := forwardTrojan(t, generation, ctx)
	if !runtimeLogs.wait(generation, L.StagePhysicalDial, L.ClassSyscall) {
		t.Fatal("actual failed socket connect lost stage/errno class")
	}
	runtimeLogs.Lock()
	observed := uint32(0)
	for _, event := range runtimeLogs.events {
		if event.Generation == generation && event.Stage == L.StagePhysicalDial {
			observed = event.Errno
			break
		}
	}
	runtimeLogs.Unlock()
	if observed == 0 {
		t.Fatal("actual syscall error was replaced with an invented zero errno")
	}
	cancel()
	assertTrojanStopped(t, manager, generation, system)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed physical dial entry not joined")
	}
}
