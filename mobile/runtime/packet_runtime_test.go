//go:build with_gvisor

package runtime_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/mobile/protection"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

var fixed = []byte("proxies:\n  - {name: sample, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: test-only}\nproxy-groups:\n  - {name: selected, type: select, proxies: [sample]}\nrules:\n  - MATCH,selected\n")

func fixedRequest(generation, transfer uint64) []byte {
	var fields map[string]any
	json.Unmarshal([]byte(envelope()), &fields)
	sum := sha256.Sum256(fixed)
	fields["inputDigest"] = "sha256:" + hex.EncodeToString(sum[:])
	fields["generation"] = generation
	fields["transferId"] = fmt.Sprint(transfer)
	encoded, _ := json.Marshal(fields)
	return encoded
}

type packetDescriptors struct {
	*descriptors
	input        chan []byte
	output       chan []byte
	ready        chan struct{}
	wake         chan struct{}
	wakeOnce     sync.Once
	nonblockWait chan struct{}
	shortWrite   bool
}

func newPacketDescriptors() *packetDescriptors {
	base := newDescriptors()
	base.open[40], base.open[41] = true, true
	return &packetDescriptors{descriptors: base, input: make(chan []byte, 64), output: make(chan []byte, 128), ready: make(chan struct{}, 64), wake: make(chan struct{})}
}
func (d *packetDescriptors) SetNonblock(int) error {
	if d.nonblockWait != nil {
		<-d.nonblockWait
	}
	return nil
}
func (d *packetDescriptors) NewWake() (int, int, error) { return 40, 41, nil }
func (d *packetDescriptors) Read(fd int, data []byte) (int, error) {
	select {
	case packet := <-d.input:
		return copy(data, packet), nil
	default:
		return 0, syscall.EAGAIN
	}
}
func (d *packetDescriptors) Write(fd int, data []byte) (int, error) {
	if fd == 41 {
		d.wakeOnce.Do(func() { close(d.wake) })
		return len(data), nil
	}
	if d.shortWrite {
		return len(data) - 1, nil
	}
	d.output <- append([]byte{}, data...)
	return len(data), nil
}
func (d *packetDescriptors) Poll(ctx context.Context, fd, wake int, write bool) error {
	if write {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.wake:
		return errors.New("wake")
	case <-d.ready:
		return nil
	}
}
func (d *packetDescriptors) inject(packet []byte) { d.input <- packet; d.ready <- struct{}{} }

var productionGate protection.Gate
var gateOnce sync.Once
var testGeneration uint64 = 99

func nextGeneration() uint64 { testGeneration++; return testGeneration }

func register(generation uint64, callback protection.Callback) {
	gateOnce.Do(func() {
		if productionGate.InstallDialerHook() != protection.Success {
			panic("hook installation")
		}
	})
	if productionGate.Register(generation, callback) != protection.Success {
		panic("gate registration")
	}
}

func TestSelectedChaChaInputStartsTheRealMobileEngineAndStopsNormally(t *testing.T) {
	input := []byte(strings.Replace(string(fixed), "aes-128-gcm", "chacha20-ietf-poly1305", 1))
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	var fields map[string]any
	json.Unmarshal(fixedRequest(generation, 1), &fields)
	sum := sha256.Sum256(input)
	fields["inputDigest"] = "sha256:" + hex.EncodeToString(sum[:])
	request, _ := json.Marshal(fields)
	system := newPacketDescriptors()
	manager := R.NewManager(system, &productionGate)
	started := manager.Start(manager.Consume(generation, 1, 9), input, request)
	stopped := manager.Stop(generation)
	if started.Outcome != "running" || !started.ForwardingActive || stopped.Phase != "stopped" || stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("real selected-cipher engine/normal-stop path failed: start=%+v stop=%+v", started, stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("descriptor %d close count %d", fd, system.closes[fd])
		}
	}
}

func TestMobileRunJoinsRealCancelledTCPHandshakeBeforeDescriptorClose(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	manager := R.NewManager(system, &productionGate)
	started := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	if started.Outcome != "running" || !started.ForwardingActive {
		t.Fatalf("real stack not ready: %+v", started)
	}
	syn := tcpPacket(50100, 1, 0, 2)
	system.inject(syn)
	select {
	case <-system.output:
	case <-time.After(time.Second):
		t.Fatal("actual SYN-ACK missing")
	}
	system.inject(syn) // retransmission cannot acquire another inner callback.
	snapshot := manager.Query(generation, 1)
	if snapshot.PendingOwners.TCPCallbacks != 1 || snapshot.PendingOwners.Constructions != 1 {
		t.Fatalf("handshake ownership missing: %+v", snapshot.PendingOwners)
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.Phase != "stopped" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("handshake not truly joined: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("descriptor %d close count %d", fd, system.closes[fd])
		}
	}
	again := manager.Stop(generation)
	if again.Cleanup != "complete" || system.closes[9] != 1 {
		t.Fatal("repeat stop repeated ownership release")
	}
}

func TestStopDuringOwnedConstructionRegistersLateWakeAndClosesIt(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	system.nonblockWait = make(chan struct{})
	manager := R.NewManager(system, &productionGate)
	started := make(chan R.Receipt, 1)
	handoff := manager.Consume(generation, 1, 9)
	go func() { started <- manager.Start(handoff, fixed, fixedRequest(generation, 1)) }()
	deadline := time.After(time.Second)
	for {
		query := manager.Query(generation, 1)
		if query.Phase == "constructing" && len(query.Resources) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("construction not reached")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	stopped := make(chan R.Receipt, 1)
	go func() { stopped <- manager.Stop(generation) }()
	deadline = time.After(time.Second)
	for {
		if manager.Query(generation, 1).Phase == "stopping" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stop not promptly admitted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(system.nonblockWait)
	<-started
	result := <-stopped
	if result.Cleanup != "complete" || result.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("late constructor forgotten: %+v", result)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("late fd %d not closed once", fd)
		}
	}
}

func TestPacketShortWriteClosesAllOwnersWithoutWritingTailAsPacket(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	system.shortWrite = true
	manager := R.NewManager(system, &productionGate)
	started := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	if started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	system.inject(tcpPacket(50101, 1, 0, 2))
	deadline := time.After(time.Second)
	var result R.Receipt
	for {
		result = manager.Query(generation, 1)
		if result.Cleanup != "pending" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("short write did not converge")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if result.Cleanup != "complete" || result.Outcome != "failed" || result.FailureCode != "TUN_WRITE" || result.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("short write disguised: %+v", result)
	}
}

func TestActualForwardingCannotBypassFailedGenerationProtection(t *testing.T) {
	generation := nextGeneration()
	protected := make(chan struct{}, 1)
	register(generation, func(uint64, uint64, uintptr) int32 {
		select {
		case protected <- struct{}{}:
		default:
		}
		return protection.PlatformFailure
	})
	system := newPacketDescriptors()
	manager := R.NewManager(system, &productionGate)
	started := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	if started.Outcome != "running" {
		t.Fatal(started.FailureCode)
	}
	system.inject(tcpPacket(50102, 1, 0, 2))
	var response []byte
	select {
	case response = <-system.output:
	case <-time.After(time.Second):
		t.Fatal("SYN-ACK missing")
	}
	if len(response) < 40 {
		t.Fatal("invalid stack packet")
	}
	serverSequence := binary.BigEndian.Uint32(response[24:28])
	system.inject(tcpPacket(50102, 2, serverSequence+1, 16))
	select {
	case <-protected:
	case <-time.After(time.Second):
		t.Fatal("actual SS physical socket never entered generation protection")
	}
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "complete" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("failed protection not joined: %+v", stopped)
	}
	if len(stopped.Connections) != 0 {
		t.Fatal("failed protected dial published a successful connection")
	}
}

type partialWake struct{ *packetDescriptors }

func (d partialWake) NewWake() (int, int, error) {
	return 40, 41, errors.New("partial syscall failure")
}

func TestPartialWakeFailureAttemptsEveryIndependentCloseAndPreservesUnknown(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	system.failed[40] = true
	manager := R.NewManager(partialWake{system}, &productionGate)
	manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	stopped := manager.Stop(generation)
	if stopped.Cleanup != "unknown" || stopped.Phase != "failed" || stopped.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("partial failure lost: %+v", stopped)
	}
	for _, fd := range []int{9, 40, 41} {
		if system.closes[fd] != 1 {
			t.Fatalf("independent fd %d not attempted", fd)
		}
	}
	if again := manager.Stop(generation); again.Cleanup != "unknown" || system.closes[40] != 1 {
		t.Fatal("unknown close guessed by retry")
	}
}

func TestStartObservationTimeoutKeepsRealConstructorOwnedUntilStop(t *testing.T) {
	generation := nextGeneration()
	register(generation, func(uint64, uint64, uintptr) int32 { return protection.Success })
	system := newPacketDescriptors()
	system.nonblockWait = make(chan struct{})
	manager := R.NewManager(system, &productionGate)
	before := time.Now()
	started := manager.Start(manager.Consume(generation, 1, 9), fixed, fixedRequest(generation, 1))
	if elapsed := time.Since(before); elapsed < 4900*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("start observation not bounded: %s", elapsed)
	}
	if started.Cleanup != "pending" || started.Tun.CloseAttempted || started.Outcome == "running" {
		t.Fatalf("timeout forgot constructor: %+v", started)
	}
	stopped := make(chan R.Receipt, 1)
	go func() { stopped <- manager.Stop(generation) }()
	deadline := time.After(time.Second)
	for {
		if manager.Query(generation, 1).Phase == "stopping" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stop admission blocked")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(system.nonblockWait)
	if result := <-stopped; result.Cleanup != "complete" || result.PendingOwners != (R.PendingOwners{}) {
		t.Fatalf("late constructor cleanup absent: %+v", result)
	}
}

func checksum(data []byte) uint16 {
	sum := uint32(0)
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func tcpPacket(port uint16, sequence, ack uint32, flags byte) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8], packet[9] = 64, 6
	copy(packet[12:16], []byte{10, 111, 0, 2})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], port)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	pseudo := append([]byte{}, packet[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}
