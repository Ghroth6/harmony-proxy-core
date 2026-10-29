//go:build with_gvisor

package runtime

import (
	"context"
	"github.com/metacubex/mihomo/config"
	"testing"
)

func TestActivePolicyRejectsStaleOrStoppedRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &config.Config{}
	m := NewManager(nil)
	m.current = &Transfer{ctx: ctx, engine: &runEngine{cfg: cfg}, receipt: Receipt{Generation: 7, CandidateDigest: "candidate", Phase: "running"}}
	calls := 0
	action := func(got *config.Config) error {
		if got != cfg {
			t.Fatal("wrong graph")
		}
		calls++
		return nil
	}
	if err := m.WithActivePolicy(7, processCoreInstance, "candidate", action); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		generation          uint64
		instance, candidate string
	}{{6, processCoreInstance, "candidate"}, {7, "old-instance", "candidate"}, {7, processCoreInstance, "old-candidate"}} {
		if err := m.WithActivePolicy(r.generation, r.instance, r.candidate, action); err == nil {
			t.Fatal("accepted stale run")
		}
	}
	cancel()
	if err := m.WithActivePolicy(7, processCoreInstance, "candidate", action); err == nil {
		t.Fatal("accepted cancelled run")
	}
	if calls != 1 {
		t.Fatal("stale request accessed graph", calls)
	}
}

func TestPolicyReadyHookIsExplicitAndCannotReplaceAnActiveOwner(t *testing.T) {
	m := NewManager(nil)
	cfg := &config.Config{}
	called := false
	m.SetPolicyReady(func(g uint64, c *config.Config) error { called = g == 3 && c == cfg; return nil })
	if err := m.preparePolicy(3, cfg); err != nil || !called {
		t.Fatal("hook did not receive initialized policy")
	}
	m.current = &Transfer{}
	defer func() {
		if recover() == nil {
			t.Fatal("hook replaced during active lifetime")
		}
	}()
	m.SetPolicyReady(nil)
}
