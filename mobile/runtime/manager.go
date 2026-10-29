package runtime

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/protection"
	"strconv"
	"sync"
	"time"
)

type Manager struct {
	mu             sync.Mutex
	system         DescriptorSystem
	transfers      map[uint64]*Transfer
	current        *Transfer
	lastGeneration uint64
	lastTransfer   uint64
	fault          bool
	gate           *protection.Gate
	policy         *policy.Engine
	policyReady    func(uint64, *config.Config) error
}
type Transfer struct {
	manager         *Manager
	mu              sync.Mutex
	policyMu        sync.Mutex
	receipt         Receipt
	fd              *descriptorOwner
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	buildDone       chan struct{}
	cleanupDone     chan struct{}
	cleanupOnce     sync.Once
	buildOnce       sync.Once
	engine          *runEngine
	rejected        bool
	startAdmitted   bool
	startRequested  bool
	generationFresh bool
}

func NewManager(system DescriptorSystem, gate ...*protection.Gate) *Manager {
	m := &Manager{system: system, transfers: map[uint64]*Transfer{}}
	if len(gate) > 0 {
		m.gate = gate[0]
	}
	return m
}

// NewManagerWithPolicy binds the already opened application-owned resource
// root for every runtime input. No root/path comes from a Start request.
func NewManagerWithPolicy(system DescriptorSystem, gate *protection.Gate, owner *policy.Engine) *Manager {
	m := NewManager(system, gate)
	m.policy = owner
	return m
}

// BindPolicy installs one process owner before runtime admission. Repeating
// the same owner is harmless; replacement would detach actual task/history
// ownership and is refused even after a successful Stop.
func (m *Manager) BindPolicy(owner *policy.Engine) error {
	if owner == nil {
		return errors.New("POLICY_OWNER_INVALID")
	}
	unlock := network.LockPath()
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy == owner {
		return nil
	}
	if m.policy != nil || m.fault {
		return errors.New("POLICY_OWNER_BUSY")
	}
	for _, transfer := range m.transfers {
		if transfer.snapshot().Cleanup != "complete" {
			return errors.New("POLICY_OWNER_BUSY")
		}
	}
	m.policy = owner
	return nil
}
func absent(generation, transfer uint64) Receipt {
	return Receipt{ContractVersion: ContractVersion, CoreInstance: processCoreInstance, Generation: generation, TransferID: strconv.FormatUint(transfer, 10), TransferState: "not-found", Phase: "absent", Outcome: "rejected", Cleanup: "unknown", FailureCode: "TRANSFER_NOT_FOUND", Stack: StackName, MTU: MTU, Tun: TunReceipt{FD: -1, MetadataBefore: zeroMetadata(), MetadataAfter: zeroMetadata(), CloseResult: -1, AfterClose: "not-observed"}, Resources: []ResourceReceipt{}, Connections: []ConnectionObservation{}}
}

// Consume must be the first operation at every C start entry, even before output
// pointer checks. A valid supplied descriptor is owned from this point onward.
func (m *Manager) Consume(generation, transfer uint64, fd int) *Transfer {
	unlockPath := network.LockPath()
	defer unlockPath()
	owned := consumeDescriptor(m.system, fd)
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transfer{manager: m, fd: owned, ctx: ctx, cancel: cancel, done: make(chan struct{}), buildDone: make(chan struct{}), cleanupDone: make(chan struct{})}
	t.receipt = absent(generation, transfer)
	t.receipt.TransferConsumed = owned.valid
	t.receipt.TransferState = "consumed"
	t.receipt.Phase = "constructing"
	t.receipt.Outcome = "pending"
	t.receipt.Cleanup = "pending"
	t.receipt.FailureCode = ""
	m.mu.Lock()
	t.generationFresh = generation > m.lastGeneration && generation <= MaxGeneration
	if t.generationFresh {
		m.lastGeneration = generation
	}
	if len(m.transfers) >= MaxTransferRecords {
		var oldest uint64
		for id, old := range m.transfers {
			receipt := old.snapshot()
			if old != m.current && receipt.Cleanup == "complete" && !receipt.OwnershipFault && (oldest == 0 || id < oldest) {
				oldest = id
			}
		}
		if oldest != 0 {
			delete(m.transfers, oldest)
		}
	}
	if transfer == 0 || transfer <= m.lastTransfer || m.transfers[transfer] != nil || len(m.transfers) >= MaxTransferRecords {
		m.fault = true
		t.receipt.OwnershipFault = true
		t.receipt.TransferState = "fault"
		t.receipt.Cleanup = "unknown"
		if old := m.transfers[transfer]; old != nil {
			old.mu.Lock()
			old.receipt.OwnershipFault = true
			old.receipt.TransferState = "fault"
			old.receipt.Cleanup = "unknown"
			old.receipt.FailureCode = "TRANSFER_FAULT"
			old.mu.Unlock()
		}
	} else {
		m.transfers[transfer] = t
		m.lastTransfer = transfer
		if t.generationFresh && owned.valid && !m.fault && (m.current == nil || m.current.snapshot().Cleanup == "complete") {
			m.current = t
		}
	}
	m.mu.Unlock()
	if t.receipt.OwnershipFault {
		t.Reject("TRANSFER_FAULT")
	}
	return t
}

// NetworkBusy includes pending descriptor transfers and retained cleanup faults,
// not only active forwarding. Submit and Consume share the path admission lock.
func (m *Manager) NetworkBusy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fault {
		return true
	}
	for _, transfer := range m.transfers {
		if transfer.snapshot().Cleanup != "complete" {
			return true
		}
	}
	return false
}
func (t *Transfer) Reject(code string) {
	t.mu.Lock()
	admitted := t.startAdmitted
	if admitted {
		t.mu.Unlock()
		t.stop()
		return
	}
	if t.rejected {
		t.mu.Unlock()
		return
	}
	t.rejected = true
	t.receipt.Phase = "failed"
	t.receipt.Outcome = "rejected"
	t.receipt.FailureCode = code
	t.mu.Unlock()
	t.cancel()
	go func() {
		t.fd.close()
		t.mu.Lock()
		t.receipt.Cleanup = "complete"
		if t.receipt.OwnershipFault || !t.fd.valid || t.fd.receipt().CloseResult != 0 {
			t.receipt.Cleanup = "unknown"
		}
		t.mu.Unlock()
		close(t.done)
		close(t.cleanupDone)
	}()
}
func (t *Transfer) snapshot() Receipt {
	t.mu.Lock()
	defer t.mu.Unlock()
	receipt := t.receipt
	receipt.Tun = t.fd.receipt()
	receipt.Resources = append([]ResourceReceipt{}, receipt.Resources...)
	receipt.Connections = append([]ConnectionObservation{}, receipt.Connections...)
	select {
	case <-t.buildDone:
		if t.engine != nil {
			t.engine.fillReceipt(&receipt)
		}
	default:
	}
	return receipt
}
func retainFault(receipt Receipt, fault bool) Receipt {
	if fault {
		receipt.OwnershipFault = true
		receipt.Cleanup = "unknown"
		receipt.TransferState = "fault"
		receipt.FailureCode = "TRANSFER_FAULT"
	}
	return receipt
}
func (m *Manager) snapshot(t *Transfer) Receipt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return retainFault(t.snapshot(), m.fault)
}
func observe(done <-chan struct{}, deadline time.Duration) {
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}
func (m *Manager) Start(t *Transfer, input, request []byte) Receipt {
	if t == nil || t.manager != m {
		return absent(0, 0)
	}
	m.mu.Lock()

	t.mu.Lock()
	if t.startRequested || t.rejected {
		t.mu.Unlock()
		m.mu.Unlock()
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	t.startRequested = true
	t.mu.Unlock()
	var refusal string
	if m.fault || t.snapshot().OwnershipFault {
		refusal = "TRANSFER_FAULT"
	} else if m.current != nil && m.current != t && m.current.snapshot().Cleanup != "complete" {
		refusal = "PREVIOUS_CLEANUP"
	} else if !t.fd.valid {
		refusal = "TUN_DESCRIPTOR"
	} else if !t.generationFresh || t.receipt.Generation != m.lastGeneration {
		refusal = "GENERATION_STALE"
	}
	if refusal == "" {
		m.current = t
	}
	m.mu.Unlock()
	if refusal != "" {
		t.Reject(refusal)
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	target, err := DecodeStart(t.receipt.Generation, mustTransfer(t.receipt.TransferID), input, request)
	if err != nil {
		t.Reject(err.Error())
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	if t.ctx.Err() != nil {
		t.Reject("START_CANCELLED")
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	if !EngineAvailable {
		t.Reject("GVISOR_REQUIRED")
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	t.mu.Lock()
	if t.rejected {
		t.mu.Unlock()
		observe(t.done, StartObservation)
		return m.snapshot(t)
	}
	t.startAdmitted = true
	t.receipt.OperationID = target.OperationID
	t.receipt.Phase = "validating"
	t.mu.Unlock()
	bytes := append([]byte{}, input...)
	go t.start(target, bytes)
	observe(t.done, StartObservation)
	return m.snapshot(t)
}
func mustTransfer(id string) uint64 { value, _ := strconv.ParseUint(id, 10, 64); return value }
func (m *Manager) Query(generation, transfer uint64) Receipt {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.current
	if transfer != 0 {
		t = m.transfers[transfer]
	}
	if t == nil || t.receipt.Generation != generation {
		return absent(generation, transfer)
	}
	return retainFault(t.snapshot(), m.fault)
}
func (m *Manager) Stop(generation uint64) Receipt {
	m.mu.Lock()
	t := m.current
	m.mu.Unlock()
	if t == nil || t.receipt.Generation != generation {
		return absent(generation, 0)
	}
	t.mu.Lock()
	rejected := t.rejected
	t.mu.Unlock()
	if !rejected {
		select {
		case <-t.cleanupDone:
			return m.snapshot(t)
		default:
			t.stop()
		}
	}
	observe(t.cleanupDone, StopObservation)
	return m.snapshot(t)
}
