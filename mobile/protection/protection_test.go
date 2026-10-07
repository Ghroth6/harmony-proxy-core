package protection_test

import (
	"errors"
	"github.com/metacubex/mihomo/mobile/protection"
	"net"
	"testing"
)

func TestUnregisteredProbeCannotProtect(t *testing.T) {
	var gate protection.Gate
	if got := gate.Probe(1, 1); got != protection.Inactive {
		t.Fatalf("unregistered probe = %d, want inactive", got)
	}
}

func TestProbeBorrowsRealSocketAndReturnsPlatformFailure(t *testing.T) {
	var gate protection.Gate
	called := false
	if got := gate.Register(1, func(generation, request uint64, fd uintptr) int32 {
		called = true
		if generation != 1 || request != 7 {
			t.Error("callback identity changed")
		}
		if !socketIsOpen(fd) {
			t.Error("borrowed socket is not live")
		}
		return 9
	}); got != protection.Success {
		t.Fatalf("register = %d", got)
	}
	if got := gate.Probe(1, 7); got != 9 {
		t.Fatalf("platform failure = %d", got)
	}
	if !called {
		t.Fatal("platform was not called")
	}
	if got := gate.Unregister(1); got != protection.Success {
		t.Fatalf("unregister = %d", got)
	}
}

func TestUnregisterClosesAdmissionAndRejectsLateSuccess(t *testing.T) {
	var gate protection.Gate
	entered, finish := make(chan struct{}), make(chan struct{})
	gate.Register(1, func(_, _ uint64, _ uintptr) int32 { close(entered); <-finish; return 0 })
	result := make(chan int32, 1)
	go func() { result <- gate.Probe(1, 1) }()
	<-entered
	if got := gate.Unregister(1); got != protection.Busy {
		t.Fatalf("in-flight unregister = %d", got)
	}
	if got := gate.Probe(1, 2); got != protection.Inactive {
		t.Errorf("new admission = %d", got)
	}
	if got := gate.Register(2, func(_, _ uint64, _ uintptr) int32 { return 0 }); got != protection.Busy {
		t.Errorf("replacement = %d", got)
	}
	close(finish)
	if got := <-result; got != protection.Inactive {
		t.Errorf("late success = %d, want inactive", got)
	}
	if got := gate.Unregister(1); got != protection.Success {
		t.Fatalf("final unregister = %d", got)
	}
}

func TestDialerFailsBeforeConnectWithoutProtection(t *testing.T) {
	var gate protection.Gate
	d := net.Dialer{Control: gate.SocketControl}
	conn, err := d.Dial("tcp4", "127.0.0.1:1")
	if conn != nil {
		conn.Close()
		t.Fatal("unprotected connection escaped")
	}
	var failure protection.Error
	if !errors.As(err, &failure) || failure.Code != protection.Inactive {
		t.Fatalf("missing protection failure: %v", err)
	}
}

func TestProbeClosesOriginalAndRetainsBoundedObservation(t *testing.T) {
	var gate protection.Gate
	gate.Register(1, func(_, _ uint64, fd uintptr) int32 { return 0 })
	for id := uint64(1); id <= 33; id++ {
		if got := gate.Probe(1, id); got != protection.Success {
			t.Fatalf("probe = %d", got)
		}
		receipt, ok := gate.ProbeObservation(1, id)
		if !ok || receipt.BeforeSocket != 1 || receipt.CloseResult != 0 {
			t.Fatalf("missing observed socket/close: %+v %v", receipt, ok)
		}
		if receipt.SocketIdentity != -1 && receipt.AfterSameSocket != 0 {
			t.Fatalf("core original socket still present: %+v", receipt)
		}
	}
	if _, ok := gate.ProbeObservation(1, 1); ok {
		t.Fatal("unbounded observation history")
	}
	receipt, ok := gate.ProbeObservation(1, 33)
	if !ok || receipt.CloseResult != 0 {
		t.Fatalf("missing actual close observation: %+v %v", receipt, ok)
	}
	if _, ok := gate.ProbeObservation(2, 33); ok {
		t.Fatal("observation crossed generation")
	}
	gate.Unregister(1)
}

func TestUnrecognizedCallbackResultCannotBecomePublicStatus(t *testing.T) {
	var gate protection.Gate
	gate.Register(1, func(_, _ uint64, _ uintptr) int32 { return 42 })
	if got := gate.Probe(1, 1); got != protection.Failed {
		t.Fatalf("unknown callback result = %d, want protection failed", got)
	}
	gate.Unregister(1)
}
