package executor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
)

type eventProvider struct {
	name        string
	kind        P.ProviderType
	vehicle     P.VehicleType
	initial     func() error
	initialized atomic.Bool
	updates     atomic.Int64
}

func (p *eventProvider) Name() string               { return p.name }
func (p *eventProvider) Type() P.ProviderType       { return p.kind }
func (p *eventProvider) VehicleType() P.VehicleType { return p.vehicle }
func (p *eventProvider) Initial() error {
	var err error
	if p.initial != nil {
		err = p.initial()
	}
	p.initialized.Store(true)
	return err
}
func (p *eventProvider) Update() error { p.updates.Add(1); return nil }

func TestProviderInitializationEventsReportSuccessFailureAndGeneration(t *testing.T) {
	failure := errors.New("provider unavailable")
	providers := map[string]*eventProvider{
		"proxy-ok":   {name: "same-name", kind: P.Proxy, vehicle: P.HTTP},
		"rule-ok":    {name: "same-name", kind: P.Rule, vehicle: P.File},
		"proxy-fail": {name: "proxy-fail", kind: P.Proxy, vehicle: P.HTTP, initial: func() error { return failure }},
		"compatible": {name: "compatible", kind: P.Proxy, vehicle: P.Compatible},
	}
	var mu sync.Mutex
	var seen []ProviderInitializationEvent
	cancel := SubscribeProviderInitialization(func(e ProviderInitializationEvent) {
		var found *eventProvider
		for _, p := range providers {
			if p.name == e.Name && p.kind == e.Type {
				found = p
			}
		}
		if found == nil || !found.initialized.Load() {
			t.Error("event sent before Initial completed")
		}
		mu.Lock()
		seen = append(seen, e)
		mu.Unlock()
	})
	defer cancel()
	loadProvider(providers, 42)
	if len(seen) != len(providers) {
		t.Fatalf("received %d initialization events", len(seen))
	}
	for _, e := range seen {
		if e.Generation != 42 || e.Succeeded != (e.Err == nil) {
			t.Fatalf("invalid result: %#v", e)
		}
		if e.Name == "proxy-fail" && !errors.Is(e.Err, failure) {
			t.Fatal("initial failure lost")
		}
	}
	// The event contract does not claim to cover Update calls.
	for _, p := range providers {
		_ = p.Update()
	}
	if len(seen) != len(providers) {
		t.Fatal("Update unexpectedly sent initialization event")
	}
	cancel()
	loadProvider(providers, 43)
	if len(seen) != len(providers) {
		t.Fatal("cancelled initialization observer still called")
	}
}

func TestProviderInitializationWaitsForInitialAndObserver(t *testing.T) {
	initialEntered, releaseInitial := make(chan struct{}), make(chan struct{})
	observerEntered, releaseObserver := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	p := &eventProvider{name: "blocked", initial: func() error { close(initialEntered); <-releaseInitial; return nil }}
	cancel := SubscribeProviderInitialization(func(e ProviderInitializationEvent) {
		if e.Name == "blocked" {
			close(observerEntered)
			<-releaseObserver
		}
	})
	defer cancel()
	go func() { loadProvider(map[string]*eventProvider{"blocked": p}, 7); close(done) }()
	<-initialEntered
	select {
	case <-done:
		t.Fatal("loadProvider returned before Initial completed")
	default:
	}
	close(releaseInitial)
	<-observerEntered
	select {
	case <-done:
		t.Fatal("loadProvider returned before observer completed")
	default:
	}
	close(releaseObserver)
	<-done
}

func TestProviderObserverMayCancelItself(t *testing.T) {
	count := 0
	var cancel func()
	cancel = SubscribeProviderInitialization(func(ProviderInitializationEvent) { count++; cancel() })
	defer cancel()
	p := &eventProvider{name: "single"}
	loadProvider(map[string]*eventProvider{"single": p}, 1)
	loadProvider(map[string]*eventProvider{"single": p}, 2)
	if count != 1 {
		t.Fatalf("self cancellation failed: %d", count)
	}
}
