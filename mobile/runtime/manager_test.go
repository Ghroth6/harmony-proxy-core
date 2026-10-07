package runtime_test

import (
	"context"
	"errors"
	R "github.com/metacubex/mihomo/mobile/runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Descriptor syscalls are the external system boundary. The runtime admission,
// independent validation and cleanup bookkeeping below are real production code.
type descriptors struct {
	mu        sync.Mutex
	open      map[int]bool
	closes    map[int]int
	failed    map[int]bool
	closeWait chan struct{}
}

func newDescriptors() *descriptors {
	return &descriptors{open: map[int]bool{9: true, 10: true}, closes: map[int]int{}, failed: map[int]bool{}}
}
func (d *descriptors) Stat(fd int) (R.DescriptorMetadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.open[fd] {
		return R.DescriptorMetadata{}, syscall.EBADF
	}
	return R.DescriptorMetadata{Observed: true, Device: "1", Inode: "2", Mode: 0x2000, RDevice: "3"}, nil
}
func (d *descriptors) Close(fd int) error {
	if d.closeWait != nil {
		<-d.closeWait
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closes[fd]++
	if d.failed[fd] {
		return errors.New("opaque close")
	}
	delete(d.open, fd)
	return nil
}
func (d *descriptors) SetNonblock(int) error                      { return nil }
func (d *descriptors) NewWake() (int, int, error)                 { return -1, -1, errors.New("wake failed") }
func (d *descriptors) Read(int, []byte) (int, error)              { return 0, errors.New("read") }
func (d *descriptors) Write(int, []byte) (int, error)             { return 0, errors.New("write") }
func (d *descriptors) Poll(context.Context, int, int, bool) error { return errors.New("poll") }

func TestEnteredRejectedDescriptorIsConsumedAndExactTransferQueryable(t *testing.T) {
	system := newDescriptors()
	manager := R.NewManager(system)
	handoff := manager.Consume(2, 7, 9)
	receipt := manager.Start(handoff, sample, []byte("{}"))
	if !receipt.TransferConsumed || receipt.TransferID != "7" || receipt.Cleanup != "complete" || !receipt.Tun.CloseAttempted || receipt.Tun.CloseResult != 0 {
		t.Fatalf("consumption lost: %+v", receipt)
	}
	specific := manager.Query(2, 7)
	if specific.Tun.AfterClose != "not-visible" || system.closes[9] != 1 {
		t.Fatalf("wrong close: %+v", specific)
	}
	missing := manager.Query(2, 8)
	if missing.Cleanup != "unknown" || missing.TransferConsumed || missing.TransferState != "not-found" {
		t.Fatalf("missing handoff replaced by clean run: %+v", missing)
	}
}

func TestCloseUnknownAndDuplicateHandoffCannotPermitNewRun(t *testing.T) {
	system := newDescriptors()
	system.failed[9] = true
	manager := R.NewManager(system)
	first := manager.Start(manager.Consume(2, 7, 9), sample, []byte("{}"))
	if first.Cleanup != "unknown" || first.Tun.CloseResult == 0 {
		t.Fatalf("opaque close reported clean: %+v", first)
	}
	next := manager.Start(manager.Consume(3, 8, 10), sample, []byte(envelope()))
	if next.Outcome != "rejected" || next.FailureCode != "PREVIOUS_CLEANUP" {
		t.Fatalf("unknown run reopened: %+v", next)
	}
	system2 := newDescriptors()
	manager2 := R.NewManager(system2)
	manager2.Start(manager2.Consume(2, 7, 9), sample, []byte("{}"))
	duplicate := manager2.Start(manager2.Consume(2, 7, 10), sample, []byte("{}"))
	if !duplicate.OwnershipFault || duplicate.Cleanup != "unknown" || !manager2.Query(2, 7).OwnershipFault || system2.closes[10] != 1 {
		t.Fatalf("duplicate handoff lost: %+v", duplicate)
	}
}

func TestObservationTimeoutRetainsActualCloseWorker(t *testing.T) {
	system := newDescriptors()
	system.closeWait = make(chan struct{})
	manager := R.NewManager(system)
	handoff := manager.Consume(2, 7, 9)
	handoff.Reject("ABI_BOUNDS")
	started := time.Now()
	receipt := manager.Query(2, 7)
	if receipt.Cleanup != "pending" || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("query blocked or forgot owned worker: %+v", receipt)
	}
	close(system.closeWait)
	deadline := time.After(time.Second)
	for {
		receipt = manager.Query(2, 7)
		if receipt.Cleanup != "pending" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("actual close never joined")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if receipt.Cleanup != "complete" || system.closes[9] != 1 {
		t.Fatalf("late close did not update receipt: %+v", receipt)
	}
}

type reusedDescriptor struct{ *descriptors }

func (d reusedDescriptor) Close(fd int) error {
	d.descriptors.Close(fd)
	d.mu.Lock()
	d.open[fd] = true
	d.mu.Unlock()
	return nil
}
func TestTunMetadataReuseIsObservationAndNeverCausesAnotherClose(t *testing.T) {
	system := reusedDescriptor{newDescriptors()}
	manager := R.NewManager(system)
	receipt := manager.Start(manager.Consume(2, 7, 9), sample, []byte("{}"))
	if receipt.Tun.AfterClose != "metadata-same" || receipt.Tun.CloseResult != 0 || receipt.Cleanup != "complete" {
		t.Fatalf("stat metadata was confused with open-file identity: %+v", receipt)
	}
	manager.Stop(2)
	manager.Query(2, 7)
	if system.closes[9] != 1 {
		t.Fatal("reused descriptor was closed again")
	}
}

func TestBadGenerationAndPreStartABIRejectionStillConsumeDescriptor(t *testing.T) {
	system := newDescriptors()
	manager := R.NewManager(system)
	receipt := manager.Start(manager.Consume(0, 7, 9), sample, []byte(envelope()))
	if receipt.Cleanup != "complete" || !receipt.TransferConsumed || receipt.Tun.CloseResult != 0 {
		t.Fatal("invalid generation leaked entered descriptor")
	}
	handoff := manager.Consume(2, 8, 10)
	handoff.Reject("ABI_BOUNDS")
	deadline := time.After(time.Second)
	for {
		receipt = manager.Query(2, 8)
		if receipt.Cleanup != "pending" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("ABI rejection not cleaned")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !receipt.TransferConsumed || receipt.Tun.CloseResult != 0 || system.closes[10] != 1 {
		t.Fatal("invalid output-pointer route lost fd ownership")
	}
}

func TestTransferCapacityFaultCannotReturnEarlierCleanRun(t *testing.T) {
	system := newDescriptors()
	manager := R.NewManager(system)
	manager.Start(manager.Consume(1, 1, 9), sample, []byte("{}"))
	pending := []*R.Transfer{}
	for id := uint64(2); id <= 64; id++ {
		fd := 1000 + int(id)
		system.open[fd] = true
		pending = append(pending, manager.Consume(id, id, fd))
	}
	system.open[1065] = true
	fault := manager.Consume(65, 65, 1065)
	manager.Start(fault, sample, []byte("{}"))
	if receipt := manager.Query(1, 0); !receipt.OwnershipFault || receipt.Cleanup != "unknown" {
		t.Fatalf("capacity failure replaced by earlier clean run: %+v", receipt)
	}
	if receipt := manager.Query(65, 65); receipt.Cleanup != "unknown" || receipt.TransferConsumed {
		t.Fatal("unstored transfer was invented")
	}
	for _, handoff := range pending {
		handoff.Reject("TEST_CLEANUP")
	}
}

func TestStopImmediatelyAfterEntryCancelsStartBeforeAnyConstructor(t *testing.T) {
	system := newDescriptors()
	manager := R.NewManager(system)
	handoff := manager.Consume(2, 7, 9)
	stopped := make(chan R.Receipt, 1)
	go func() { stopped <- manager.Stop(2) }()
	deadline := time.After(time.Second)
	for {
		if manager.Query(2, 7).Phase == "stopping" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("entered transfer not available to immediate stop")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	started := manager.Start(handoff, sample, []byte(envelope()))
	if started.Cleanup != "complete" || started.FailureCode != "START_CANCELLED" || len(started.Resources) != 0 {
		t.Fatalf("stop allowed later resource construction: %+v", started)
	}
	if receipt := <-stopped; receipt.Cleanup != "complete" || system.closes[9] != 1 {
		t.Fatal("entry cancellation did not converge")
	}
}
