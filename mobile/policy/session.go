package policy

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/component/dialer"
	"io"
	"sort"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/platformnetwork"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
)

type resourceSession struct {
	engine                        *Engine
	prepared                      contract.PreparedContext
	providers                     map[string]P.RuleProvider
	geo                           *geodata.Prepared
	fakeIPState                   *fakeip.ScopedPersistence
	mu                            sync.Mutex
	activated, retired            bool
	generation, networkGeneration uint64
	adopted                       map[string]ResourceVersion
	events                        []ResourceEvent
	historyTruncated              bool
	closeErr                      error
	workerRoot                    context.Context
	workerCancel                  context.CancelFunc
	workers                       int
	changed                       chan struct{}
	failedCloses                  map[io.Closer]error
	pendingAdoptions              map[string]ResourceVersion
}

func newResourceSession(engine *Engine, prepared contract.PreparedContext, providers map[string]P.RuleProvider) (*resourceSession, error) {
	s := &resourceSession{engine: engine, prepared: prepared, providers: providers, adopted: map[string]ResourceVersion{}, events: []ResourceEvent{}, changed: make(chan struct{}), failedCloses: map[io.Closer]error{}, pendingAdoptions: map[string]ResourceVersion{}}
	for _, resource := range prepared.Resources {
		s.adopted[resource.RefID] = version(resource)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.closed || engine.closeErr != nil {
		return nil, errors.New("POLICY_RESOURCE_OWNER_RETIRED")
	}
	engine.sessions[s] = struct{}{}
	return s, nil
}
func version(r contract.Resource) ResourceVersion {
	return ResourceVersion{RefID: r.RefID, SourceDigest: r.SourceDigest, ContentDigest: r.ContentDigest, ByteLength: r.ByteLength, RelativePath: r.RelativePath}
}

func (s *resourceSession) ActivateScheduled(root context.Context) error {
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return context.Canceled
	}
	if s.activated {
		s.mu.Unlock()
		return nil
	}
	generation := forwarding.Generation(root)
	s.mu.Unlock()
	if generation == 0 {
		return errors.New("POLICY_RESOURCE_ACTIVATION_INVALID")
	}
	active, finish, err := forwarding.Acquire(root)
	if err != nil {
		return errors.New("POLICY_RESOURCE_ACTIVATION_INVALID")
	}
	defer finish()
	bound := forwarding.SnapshotManagementNetwork(active)
	_, finishNetwork, err := forwarding.AcquireManagementNetwork(bound)
	if err != nil {
		return errors.New("POLICY_RESOURCE_ACTIVATION_INVALID")
	}
	defer finishNetwork()
	observed, available := platformnetwork.Current()
	if !available || !observed.Online || observed.Generation == 0 {
		return errors.New("POLICY_RESOURCE_ACTIVATION_INVALID")
	}
	s.engine.mu.Lock()
	if s.engine.current != nil && s.engine.current != s {
		s.engine.mu.Unlock()
		return errors.New("POLICY_RESOURCE_OWNER_BUSY")
	}
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		s.engine.mu.Unlock()
		return context.Canceled
	}
	s.activated = true
	s.workerRoot, s.workerCancel = context.WithCancel(bound)
	bound = dialer.WithWorkerOwner(s.workerRoot, s)
	s.generation = generation
	s.networkGeneration = observed.Generation
	s.engine.current = s
	s.mu.Unlock()
	s.engine.mu.Unlock()
	for _, provider := range s.providers {
		if scheduled, ok := provider.(interface{ ActivateScheduled(context.Context) error }); ok {
			if err := scheduled.ActivateScheduled(bound); err != nil {
				s.Cancel()
				return errors.New("POLICY_RESOURCE_ACTIVATION_INVALID")
			}
		}
	}
	return nil
}
func (s *resourceSession) Cancel() {
	s.mu.Lock()
	s.retired = true
	if s.workerCancel != nil {
		s.workerCancel()
	}
	s.mu.Unlock()
	for _, provider := range s.providers {
		if owner, ok := provider.(interface{ Cancel() }); ok {
			owner.Cancel()
		}
	}
	if s.fakeIPState != nil {
		s.fakeIPState.Cancel()
	}
}
func (s *resourceSession) Wait(ctx context.Context) error {
	var errorsFound []error
	for _, provider := range s.providers {
		if owner, ok := provider.(interface{ Wait(context.Context) error }); ok {
			errorsFound = append(errorsFound, owner.Wait(ctx))
		}
	}
	s.mu.Lock()
	for s.workers != 0 {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
		s.mu.Lock()
	}
	errorsFound = append(errorsFound, s.closeErr)
	s.mu.Unlock()
	if err := errors.Join(errorsFound...); err != nil {
		return err
	}
	if s.fakeIPState != nil {
		if err := s.fakeIPState.Wait(ctx); err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.recordClose(err)
				s.engine.retainClose(s.fakeIPState, err)
			}
			return err
		}
	}
	if s.geo != nil {
		if err := s.geo.Close(); err != nil {
			s.recordClose(err)
			return errors.New("POLICY_RESOURCE_CLOSE_FAILED")
		}
	}
	s.engine.mu.Lock()
	if s.engine.current == s {
		s.engine.current = nil
	}
	delete(s.engine.sessions, s)
	s.engine.mu.Unlock()
	return nil
}
func (s *resourceSession) AcquireWorker(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if !s.activated || s.retired || s.workerRoot.Err() != nil {
		s.mu.Unlock()
		return nil, nil, context.Canceled
	}
	s.workers++
	root := s.workerRoot
	s.mu.Unlock()
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(root, cancel)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			stop()
			cancel()
			s.mu.Lock()
			s.workers--
			close(s.changed)
			s.changed = make(chan struct{})
			s.mu.Unlock()
		})
	}
	return dialer.WithWorkerOwner(owned, s), finish, nil
}
func (s *resourceSession) RetainWorkerCloseFailure(closer io.Closer, err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedCloses[closer] = err
	s.closeErr = errors.Join(s.closeErr, errors.New("POLICY_RESOURCE_CLOSE_FAILED"))
}
func (s *resourceSession) reserveAdoption(value ResourceVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired || s.closeErr != nil {
		return errors.New("POLICY_RESOURCE_OWNER_RETIRED")
	}
	var total int64
	for ref, current := range s.adopted {
		if ref == value.RefID {
			current = value
		} else if pending, ok := s.pendingAdoptions[ref]; ok {
			current = pending
		}
		total += current.ByteLength
	}
	if total > contract.MaxTotalBytes {
		return errors.New("POLICY_RESOURCE_BOUNDS")
	}
	s.pendingAdoptions[value.RefID] = value
	return nil
}
func (s *resourceSession) finishAdoption(ref string) {
	s.mu.Lock()
	delete(s.pendingAdoptions, ref)
	s.mu.Unlock()
}
func (s *resourceSession) recordClose(err error) {
	if err != nil {
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, errors.New("POLICY_RESOURCE_CLOSE_FAILED"))
		s.mu.Unlock()
	}
}
func (s *resourceSession) record(task, ref, stage, code string, value ResourceVersion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sequence := strconv.FormatUint(resourceEventSequence.Add(1), 10)
	event := ResourceEvent{Sequence: sequence, TaskID: task, RefID: ref, Generation: s.generation, NetworkGeneration: s.networkGeneration, Stage: stage, Code: code, ContentDigest: value.ContentDigest, ByteLength: value.ByteLength, RelativePath: value.RelativePath}
	if len(s.events) == 128 {
		copy(s.events, s.events[1:])
		s.events = s.events[:127]
		s.historyTruncated = true
	}
	s.events = append(s.events, event)
	if stage == "adopted" {
		s.adopted[ref] = value
	}
}
func (s *resourceSession) observe(receipt ResourcesReceipt) ResourcesReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.activated || s.generation != receipt.Generation {
		return receipt
	}
	receipt.Category = "observed"
	receipt.CandidateDigest = s.prepared.CandidateDigest
	receipt.InitialManifestDigest = s.prepared.ResourceManifestDigest
	for _, value := range s.adopted {
		receipt.Adopted = append(receipt.Adopted, value)
	}
	sort.Slice(receipt.Adopted, func(i, j int) bool { return receipt.Adopted[i].RefID < receipt.Adopted[j].RefID })
	receipt.Events = append(receipt.Events, s.events...)
	receipt.HistoryTruncated = s.historyTruncated
	return receipt
}
