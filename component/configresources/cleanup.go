// Package configresources owns resources created for a configuration candidate.
// It never consults or retires the currently published configuration.
package configresources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type taskOwner interface {
	Cancel()
	Wait(context.Context) error
}

type testOwner interface {
	CancelURLTests()
	WaitURLTests(context.Context) error
}

var (
	ErrTransferred    = errors.New("candidate ownership has been transferred")
	ErrCleanupStarted = errors.New("candidate cleanup has already started")
)

// Set's zero value is ready for use. Registration is allowed only before Close.
// AddProxy and AddProvider do not recursively adopt borrowed group members or
// provider nodes: the constructor must register objects it actually owns.
type Set struct {
	mu          sync.Mutex
	proxies     map[C.Proxy]struct{}
	adapters    map[C.ProxyAdapter]struct{}
	providers   map[P.Provider]struct{}
	done        chan struct{}
	err         error
	transferred bool
}

func (s *Set) AddProxy(p C.Proxy) {
	if p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkOpen()
	if s.proxies == nil {
		s.proxies = make(map[C.Proxy]struct{})
	}
	s.proxies[p] = struct{}{}
	s.addAdapter(p.Adapter())
}

func (s *Set) AddAdapter(a C.ProxyAdapter) {
	if a == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkOpen()
	s.addAdapter(a)
}

func (s *Set) addAdapter(a C.ProxyAdapter) {
	if a == nil {
		return
	}
	if s.adapters == nil {
		s.adapters = make(map[C.ProxyAdapter]struct{})
	}
	s.adapters[a] = struct{}{}
}

func (s *Set) AddProvider(p P.Provider) {
	if p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkOpen()
	if s.providers == nil {
		s.providers = make(map[P.Provider]struct{})
	}
	s.providers[p] = struct{}{}
}

func (s *Set) checkOpen() {
	if s.done != nil || s.transferred {
		panic("registering a resource after candidate ownership ended")
	}
}

// CheckTransfer rejects a discarded candidate before the caller retires its
// active configuration. Transfer checks again at the actual publication point.
func (s *Set) CheckTransfer() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return ErrCleanupStarted
	}
	return nil
}

// Transfer hands ownership to the runtime without closing anything. It drops
// candidate-only references so later provider refreshes retain their existing
// lifetime behavior. Reapplying the same published object is allowed.
func (s *Set) Transfer() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return ErrCleanupStarted
	}
	s.transferred = true
	s.proxies, s.adapters, s.providers = nil, nil, nil
	return nil
}

// Close starts cleanup once and waits up to ctx's deadline. Cleanup itself is
// not cancelled by ctx: a timeout retains the real work in CleanupError, whose
// Wait method can be called again without issuing a second Close to a resource.
func (s *Set) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.transferred {
		s.mu.Unlock()
		return ErrTransferred
	}
	if s.done == nil {
		s.done = make(chan struct{})
		go s.cleanup()
	}
	done := s.done
	s.mu.Unlock()
	// Prefer a completed result even if the supplied wait context expired.
	select {
	case <-done:
		return s.result()
	default:
	}
	select {
	case <-done:
		return s.result()
	case <-ctx.Done():
		return &CleanupError{set: s, cause: ctx.Err()}
	}
}

func (s *Set) result() error {
	if s.err != nil {
		return &CleanupError{set: s, cause: s.err}
	}
	return nil
}

func (s *Set) cleanup() {
	// Cancel every owner before waiting on any one of them. Candidate health
	// checks can otherwise keep a sibling provider or its adapter alive.
	for p := range s.providers {
		if owner, ok := p.(taskOwner); ok {
			owner.Cancel()
		}
	}
	for p := range s.proxies {
		if owner, ok := p.(testOwner); ok {
			owner.CancelURLTests()
		}
	}
	var waits []func() error
	for p := range s.providers {
		p := p
		if owner, ok := p.(taskOwner); ok {
			waits = append(waits, func() error { return wrap("provider", p.Name(), owner.Wait(context.Background())) })
		} else if closer, ok := p.(io.Closer); ok {
			waits = append(waits, func() error { return wrap("provider", p.Name(), closer.Close()) })
		}
	}
	for p := range s.proxies {
		p := p
		if owner, ok := p.(testOwner); ok {
			waits = append(waits, func() error { return wrap("proxy tests", p.Name(), owner.WaitURLTests(context.Background())) })
		}
	}
	if err := runAll(waits); err != nil {
		// A task that could not finish still owns the adapter it may be using.
		s.err = err
		close(s.done)
		return
	}
	var closes []func() error
	for a := range s.adapters {
		a := a
		closes = append(closes, func() error { return wrap("proxy", a.Name(), a.Close()) })
	}
	s.err = runAll(closes)
	close(s.done)
}

func runAll(actions []func() error) error {
	errs := make([]error, len(actions))
	var wg sync.WaitGroup
	for i, action := range actions {
		i, action := i, action // go.mod retains pre-Go 1.22 range semantics.
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = action() }()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func wrap(kind, name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %q: %w", kind, name, err)
}

// CleanupError keeps ownership of an unfinished or failed cleanup operation.
// A true Close failure remains a failure on subsequent Wait calls.
type CleanupError struct {
	set   *Set
	cause error
}

func (e *CleanupError) Error() string                  { return "candidate cleanup: " + e.cause.Error() }
func (e *CleanupError) Unwrap() error                  { return e.cause }
func (e *CleanupError) Wait(ctx context.Context) error { return e.set.Close(ctx) }

// WaitCleanup joins only cleanup operations contained in err. It deliberately
// omits the original parse/apply error, which cannot be fixed by waiting.
func WaitCleanup(ctx context.Context, err error) error {
	seen := make(map[*Set]struct{})
	var waits []func() error
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if cleanup, ok := err.(*CleanupError); ok {
			if _, exists := seen[cleanup.set]; !exists {
				seen[cleanup.set] = struct{}{}
				waits = append(waits, func() error { return cleanup.Wait(ctx) })
			}
			return
		}
		switch err := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range err.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(err.Unwrap())
		}
	}
	visit(err)
	return runAll(waits)
}
