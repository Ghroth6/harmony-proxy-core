//go:build with_gvisor

package runtime

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"syscall"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/mobile/network"
	"github.com/metacubex/mihomo/mobile/protection"
	"github.com/metacubex/mihomo/mobile/validation"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type observation struct {
	value   ConnectionObservation
	tracker statistic.Tracker
}

const EngineAvailable = true

type runEngine struct {
	transfer            *Transfer
	cfg                 *config.Config
	published           bool
	prepared            bool
	endpoint            *channel.Endpoint
	stack               *stack.Stack
	book                *tcpBook
	bound               C.Tunnel
	root                context.Context
	wakeRead, wakeWrite *descriptorOwner
	pumps               sync.WaitGroup
	observationCancel   func()
	observations        []observation
}

func (t *Transfer) phase(phase string) {
	t.mu.Lock()
	changed := false
	if t.ctx.Err() == nil {
		changed = t.receipt.Phase != phase
		t.receipt.Phase = phase
	}
	t.mu.Unlock()
	if changed {
		switch phase {
		case "constructing":
			log.MobilePhase(t.receipt.Generation, log.StageConstructing)
		case "starting":
			log.MobilePhase(t.receipt.Generation, log.StageStarting)
		}
	}
}
func (t *Transfer) resource(kind, state string, result int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for index, item := range t.receipt.Resources {
		if item.Kind == kind {
			t.receipt.Resources[index] = ResourceReceipt{Kind: kind, State: state, CloseResult: result}
			return
		}
	}
	t.receipt.Resources = append(t.receipt.Resources, ResourceReceipt{Kind: kind, State: state, CloseResult: result})
}
func (t *Transfer) failure(code string) {
	t.mu.Lock()
	first := t.receipt.FailureCode == ""
	if t.receipt.FailureCode == "" {
		t.receipt.FailureCode = code
		t.receipt.Outcome = "failed"
	}
	t.mu.Unlock()
	if first {
		log.MobilePhase(t.receipt.Generation, log.StageRuntimeFailed)
	}
	t.stop()
}
func (t *Transfer) start(target StartRequest, input []byte) {
	engine := &runEngine{transfer: t}
	t.mu.Lock()
	t.engine = engine
	t.mu.Unlock()
	defer func() {
		if recover() != nil {
			t.resource("construction", "unknown", 1)
			t.failure("CORE_PANIC")
		}
		close(t.buildDone)
		t.buildOnce.Do(func() { close(t.done) })
		if t.ctx.Err() != nil {
			t.stop()
		}
	}()
	// A shape-only preparedPolicy cannot authorize resources or forwarding.
	// Replace this gate only with the typed policy identity/builder path.
	if target.PreparedPolicy != nil {
		t.failure("POLICY_RUNTIME_NOT_READY")
		return
	}
	validationReceipt := validation.Validate(target.OperationID, input)
	covered := false
	extended := false
	for _, coverage := range validationReceipt.Covered {
		if coverage == "m1b-fixed-ipv4-tcp" {
			covered = true
		}
		if coverage == "mobile-proxy-ipv4-tcp-v2" {
			covered = true
			extended = true
		}
	}
	if validationReceipt.Category != "pass" || validationReceipt.InputDigest != target.InputDigest || !covered {
		t.failure("CANDIDATE_RECHECK")
		return
	}
	if t.ctx.Err() != nil {
		return
	}
	t.phase("constructing")
	raw, err := config.UnmarshalRawConfig(input)
	if err != nil {
		t.failure("CANDIDATE_FORMAT")
		return
	}
	if extended || target.NetworkGeneration != 0 {
		needsDNS := false
		for _, node := range raw.Proxy {
			server, _ := node["server"].(string)
			if _, err := netip.ParseAddr(server); err != nil {
				needsDNS = true
			}
		}
		accepted, code := network.Accepted(target.NetworkGeneration, needsDNS)
		if code != "" {
			t.failure(code)
			return
		}
		t.mu.Lock()
		t.receipt.NetworkGeneration = accepted
		t.mu.Unlock()
	}
	if extended {
		engine.cfg, err = config.BuildMobileSelectedCandidate(raw)
	} else {
		engine.cfg, err = config.BuildMobileFixedCandidate(raw)
	}
	if engine.cfg != nil {
		t.resource("candidate", "acquired", -1)
	}
	if err != nil {
		t.failure("CANDIDATE_CONSTRUCT")
		return
	}
	if t.ctx.Err() != nil {
		return
	}
	if t.manager.gate == nil || !t.manager.gate.Ready(target.Generation) {
		t.failure("PROTECTION_NOT_READY")
		return
	}
	engine.root = protection.WithGeneration(t.ctx, target.Generation)
	tunnel.EnableForwardingLifecycle()
	if err = tunnel.PrepareForwarding(engine.root, target.Generation); err != nil {
		t.failure("FORWARDING_PREPARE")
		return
	}
	engine.prepared = true
	t.resource("forwarding", "acquired", -1)
	engine.bound, err = tunnel.BoundForwardingTunnel(target.Generation)
	if err != nil {
		t.failure("FORWARDING_BIND")
		return
	}
	if err = t.manager.system.SetNonblock(t.fd.fd); err != nil {
		t.failure("TUN_NONBLOCK")
		return
	}
	read, write, err := t.manager.system.NewWake()
	// Register every returned valid descriptor even on a partial syscall failure.
	if read >= 0 {
		engine.wakeRead = consumeDescriptor(t.manager.system, read)
		t.resource("wake-read", "acquired", -1)
	}
	if write >= 0 {
		engine.wakeWrite = consumeDescriptor(t.manager.system, write)
		t.resource("wake-write", "acquired", -1)
	}
	if err != nil || engine.wakeRead == nil || !engine.wakeRead.valid || engine.wakeWrite == nil || !engine.wakeWrite.valid {
		t.failure("WAKE_CONSTRUCT")
		return
	}
	if t.ctx.Err() != nil {
		return
	}
	engine.endpoint = channel.New(PacketQueue, MTU, "")
	engine.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	t.resource("packet-stack", "acquired", -1)
	engine.book = newTCPBook(engine)
	engine.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, engine.book.handlePacket)
	if errorCode := engine.stack.CreateNICWithOptions(1, engine.endpoint, stack.NICOptions{}); errorCode != nil {
		t.failure("STACK_NIC")
		return
	}
	engine.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	if engine.stack.SetSpoofing(1, true) != nil || engine.stack.SetPromiscuousMode(1, true) != nil {
		t.failure("STACK_OPTIONS")
		return
	}
	if t.ctx.Err() != nil {
		return
	}
	if err = engine.cfg.ActivateMobileNetwork(target.Generation); err != nil {
		t.failure("CANDIDATE_NETWORK_ACTIVATE")
		return
	}
	if err = executor.PublishMobileFixed(t.ctx, engine.cfg); err != nil {
		t.failure("CANDIDATE_PUBLISH")
		return
	}
	engine.published = true
	engine.observationCancel = statistic.DefaultManager.SubscribeConnections(engine.observeConnection)
	t.phase("starting")
	// Keep activation, pump registration and Stop mutually exclusive. No goroutine
	// is launched before its owner has been added, even if cancellation races.
	if t.ctx.Err() != nil {
		return
	}
	if err = tunnel.ActivateForwarding(target.Generation); err == nil {
		err = executor.ActivateMobileFixed(engine.cfg)
	}
	if err != nil {
		t.failure("ENTRY_ACTIVATE")
		return
	}
	t.mu.Lock()
	if t.ctx.Err() != nil {
		t.mu.Unlock()
		return
	}
	engine.book.activate()
	t.receipt.PendingOwners.Pumps = 2
	engine.pumps.Add(2)
	go engine.readPump()
	go engine.writePump()
	t.receipt.Phase = "running"
	t.receipt.Outcome = "running"
	t.receipt.ForwardingActive = true
	t.mu.Unlock()
	log.MobilePhase(target.Generation, log.StageRunning)
}
func (t *Transfer) stop() {
	t.mu.Lock()
	changed := t.receipt.Phase != "stopping" && t.receipt.Cleanup != "complete"
	t.cancel()
	t.receipt.ForwardingActive = false
	if t.receipt.Cleanup != "complete" {
		t.receipt.Phase = "stopping"
		if t.receipt.Outcome != "failed" {
			t.receipt.Outcome = "pending"
		}
	}
	admitted := t.startAdmitted
	t.mu.Unlock()
	if changed {
		log.MobilePhase(t.receipt.Generation, log.StageStopping)
	}
	if t.manager.gate != nil {
		t.manager.gate.Unregister(t.receipt.Generation)
	}
	if !admitted {
		return
	}
	t.cleanupOnce.Do(func() { go func() { <-t.buildDone; t.cleanup() }() })
}
func (t *Transfer) cleanup() {
	engine := t.engine
	unknown := false
	if engine != nil {
		if engine.book != nil {
			engine.book.stopAdmission()
		}
		if engine.prepared {
			tunnel.CancelForwarding()
		}
		if engine.wakeWrite != nil {
			if _, err := t.manager.system.Write(engine.wakeWrite.fd, []byte{1}); err != nil && !errors.Is(err, syscall.EAGAIN) {
				unknown = true
				t.resource("wake-write", "unknown", errno(err))
			}
		}
		if engine.endpoint != nil {
			engine.endpoint.Attach(nil)
			engine.endpoint.Close()
		}
		engine.pumps.Wait()
		if engine.book != nil {
			engine.book.waitConstructions()
		}
		if engine.stack != nil {
			engine.stack.Close()
			for _, endpoint := range engine.stack.RegisteredEndpoints() {
				endpoint.Abort()
			}
			for _, endpoint := range engine.stack.CleanupEndpoints() {
				endpoint.Abort()
			}
		}
		if engine.book != nil {
			engine.book.waitCallbacks()
			if engine.book.isFault() {
				unknown = true
			}
		}
		if engine.prepared {
			if err := tunnel.StopForwarding(context.Background()); err != nil {
				log.MobileFailure(t.receipt.Generation, log.StageCleanupFailed, err)
				unknown = true
				t.resource("forwarding", "unknown", 1)
			} else {
				t.resource("forwarding", "closed", 0)
			}
		}
		if engine.stack != nil {
			engine.stack.Wait()
			t.resource("packet-stack", "closed", 0)
		}
		if engine.observationCancel != nil {
			engine.observationCancel()
		}
	}
	// Independent safe closes all begin, even when one syscall or retirement hangs.
	var closes sync.WaitGroup
	for _, entry := range []struct {
		kind  string
		owner *descriptorOwner
	}{{"tun", t.fd}, {"wake-read", ownerRead(engine)}, {"wake-write", ownerWrite(engine)}} {
		if entry.owner == nil {
			continue
		}
		entry := entry
		closes.Add(1)
		t.resource(entry.kind, "closing", -1)
		go func() {
			defer closes.Done()
			entry.owner.close()
			receipt := entry.owner.receipt()
			if !receipt.CloseAttempted || receipt.CloseResult != 0 {
				t.resource(entry.kind, "unknown", receipt.CloseResult)
			} else {
				t.resource(entry.kind, "closed", 0)
			}
		}()
	}
	if engine != nil && engine.cfg != nil {
		closes.Add(1)
		t.resource("candidate", "closing", -1)
		go func() {
			defer closes.Done()
			var err error
			if engine.published {
				err = executor.RetireConfig(context.Background())
			} else {
				err = engine.cfg.Discard(context.Background())
			}
			if err != nil {
				log.MobileFailure(t.receipt.Generation, log.StageCleanupFailed, err)
				t.resource("candidate", "unknown", 1)
			} else {
				t.resource("candidate", "closed", 0)
			}
		}()
	}
	closes.Wait()
	if t.manager.gate != nil {
		status := t.manager.gate.Unregister(t.receipt.Generation)
		if status == protection.Busy {
			unknown = true
		}
	}
	t.mu.Lock()
	for _, entry := range t.receipt.Resources {
		if entry.State == "unknown" {
			unknown = true
		}
	}
	if t.receipt.OwnershipFault {
		unknown = true
	}
	if unknown {
		t.receipt.Cleanup = "unknown"
		t.receipt.Phase = "failed"
		t.receipt.Outcome = "failed"
		if t.receipt.FailureCode == "" {
			t.receipt.FailureCode = "CLEANUP_UNKNOWN"
		}
	} else {
		t.receipt.Cleanup = "complete"
		t.receipt.Phase = "stopped"
		if t.receipt.Outcome != "failed" {
			t.receipt.Outcome = "stopped"
		}
	}
	close(t.cleanupDone)
	t.mu.Unlock()
	if unknown {
		log.MobilePhase(t.receipt.Generation, log.StageCleanupFailed)
	} else {
		log.MobilePhase(t.receipt.Generation, log.StageStopped)
	}
}
func ownerRead(engine *runEngine) *descriptorOwner {
	if engine == nil {
		return nil
	}
	return engine.wakeRead
}
func ownerWrite(engine *runEngine) *descriptorOwner {
	if engine == nil {
		return nil
	}
	return engine.wakeWrite
}
func (e *runEngine) pumpDone() {
	e.transfer.mu.Lock()
	e.transfer.receipt.PendingOwners.Pumps--
	e.transfer.mu.Unlock()
	e.pumps.Done()
}
func (e *runEngine) readPump() {
	defer e.pumpDone()
	system := e.transfer.manager.system
	data := make([]byte, MTU+1)
	for {
		if e.transfer.ctx.Err() != nil {
			return
		}
		n, err := system.Read(e.transfer.fd.fd, data)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			if err = system.Poll(e.transfer.ctx, e.transfer.fd.fd, e.wakeRead.fd, false); err != nil {
				if e.transfer.ctx.Err() == nil {
					log.MobileFailure(e.transfer.receipt.Generation, log.StageTunRead, err)
					e.transfer.failure("TUN_READ_POLL")
				}
				return
			}
			continue
		}
		if err != nil || n <= 0 || n > MTU {
			log.MobileFailure(e.transfer.receipt.Generation, log.StageTunRead, err)
			e.transfer.failure("TUN_READ")
			return
		}
		// IPv4/TCP only; unknown protocols are discarded without constructing sockets.
		if n < 20 || data[0]>>4 != 4 || data[9] != byte(tcp.ProtocolNumber) {
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte{}, data[:n]...))})
		e.endpoint.InjectInbound(ipv4.ProtocolNumber, packet)
		packet.DecRef()
	}
}
func (e *runEngine) writePump() {
	defer e.pumpDone()
	system := e.transfer.manager.system
	for {
		packet := e.endpoint.ReadContext(e.transfer.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		data := view.AsSlice()
		var err error
		for {
			if e.transfer.ctx.Err() != nil {
				err = e.transfer.ctx.Err()
				break
			}
			var n int
			n, err = system.Write(e.transfer.fd.fd, data)
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				err = system.Poll(e.transfer.ctx, e.transfer.fd.fd, e.wakeRead.fd, true)
				if err == nil {
					continue
				}
			}
			if err == nil && n != len(data) {
				err = errors.New("short packet write")
			}
			break
		}
		view.Release()
		packet.DecRef()
		if err != nil {
			if e.transfer.ctx.Err() == nil {
				log.MobileFailure(e.transfer.receipt.Generation, log.StageTunWrite, err)
				e.transfer.failure("TUN_WRITE")
			}
			return
		}
	}
}
func (e *runEngine) observeConnection(tracker statistic.Tracker) {
	info := tracker.Info()
	if info.Metadata.ForwardingGeneration != e.transfer.receipt.Generation || !info.Metadata.DstIP.Is4() {
		return
	}
	node := "redacted"
	if len(info.Chain) > 0 && safeID.MatchString(info.Chain[0]) {
		node = info.Chain[0]
	}
	rule := "redacted"
	if safeID.MatchString(info.Rule) {
		rule = info.Rule
	}
	e.transfer.mu.Lock()
	defer e.transfer.mu.Unlock()
	sequence := uint64(1)
	if len(e.observations) > 0 {
		sequence = e.observations[len(e.observations)-1].value.Sequence + 1
	}
	if sequence > MaxGeneration {
		sequence = MaxGeneration
	}
	value := ConnectionObservation{Sequence: sequence, TargetIPv4: info.Metadata.DstIP.String(), TargetPort: info.Metadata.DstPort, Node: node, Rule: rule}
	if len(e.observations) == 16 {
		e.observations = e.observations[1:]
	}
	e.observations = append(e.observations, observation{value: value, tracker: tracker})
}
func (e *runEngine) fillReceipt(receipt *Receipt) {
	if e.book != nil {
		receipt.PendingOwners.TCPCallbacks, receipt.PendingOwners.Constructions, receipt.PendingOwners.Forwarding = e.book.counts()
	}
	receipt.Connections = []ConnectionObservation{}
	for _, record := range e.observations {
		value := record.value
		value.Upload = record.tracker.Info().UploadTotal.Load()
		value.Download = record.tracker.Info().DownloadTotal.Load()
		receipt.Connections = append(receipt.Connections, value)
	}
}
func address(address tcpip.Address) netip.Addr { return netip.AddrFrom4(address.As4()) }
