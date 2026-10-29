package runtime

import (
	"errors"
	"github.com/metacubex/mihomo/config"
)

// SetPolicyReady binds an application's local selection restoration before the
// first run. It runs after provider initialization and before client ingress.
func (m *Manager) SetPolicyReady(ready func(uint64, *config.Config) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		panic("policy hook must be installed before runtime admission")
	}
	m.policyReady = ready
}

func (m *Manager) preparePolicy(generation uint64, cfg *config.Config) error {
	m.mu.Lock()
	ready := m.policyReady
	m.mu.Unlock()
	if ready != nil {
		return ready(generation, cfg)
	}
	return nil
}

// WithActivePolicy borrows the current graph; it does not transfer ownership.
// The callback must not stop this manager or retain cfg beyond the call.
// Cleanup joins this access before retiring providers and their nodes.
func (m *Manager) WithActivePolicy(generation uint64, instance, candidate string, action func(*config.Config) error) error {
	m.mu.Lock()
	t := m.current
	fault := m.fault
	m.mu.Unlock()
	if t == nil || fault {
		return errors.New("NODES_RUN_CHANGED")
	}
	t.policyMu.Lock()
	defer t.policyMu.Unlock()
	t.mu.Lock()
	valid := instance == processCoreInstance && t.receipt.Generation == generation && t.receipt.CandidateDigest == candidate && t.receipt.Phase == "running" && t.ctx.Err() == nil
	t.mu.Unlock()
	if !valid {
		return errors.New("NODES_RUN_CHANGED")
	}
	return t.withPolicy(action)
}
