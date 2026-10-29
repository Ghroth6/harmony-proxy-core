// Package lifecycle owns deferred local resources across preparation and use.
package lifecycle

import (
	"errors"
	"net"
	"sync"
)

type entry struct {
	start, close func() error
	deferred     bool
	resource     Resource
	startErr     error
}

// Resource is inactive until Start. Close also accepts an unstarted resource.
type Resource interface {
	Start() error
	Close() error
}

type Group struct {
	mu             sync.Mutex
	entries        map[*entry]struct{}
	shared         map[any]*entry
	active, closed bool
	done           chan struct{}
	err            error
}

// GetOrAdd shares one resource per comparable key within this owner, never
// across owners. create must only construct an inactive resource and must not
// call back into the Group. A failed Start stays owned and is not hidden by reuse.
func (g *Group) GetOrAdd(key any, create func() Resource) (Resource, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, net.ErrClosed
	}
	if e, ok := g.shared[key]; ok {
		return e.resource, e.startErr
	}
	r := create()
	e := &entry{start: r.Start, close: r.Close, resource: r}
	if g.entries == nil {
		g.entries = map[*entry]struct{}{}
	}
	if g.shared == nil {
		g.shared = map[any]*entry{}
	}
	g.entries[e] = struct{}{}
	g.shared[key] = e
	if g.active {
		e.startErr = e.start()
	}
	return r, e.startErr
}

// Add transfers a resource even when activation fails, so Close still owns it.
func (g *Group) Add(start, close func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.Join(net.ErrClosed, close())
	}
	if g.entries == nil {
		g.entries = map[*entry]struct{}{}
	}
	e := &entry{start: start, close: close}
	g.entries[e] = struct{}{}
	if g.active {
		return start()
	}
	return nil
}

// Adopt lets an individually retired node release its registration, so refreshes
// do not retain every historical node until the configuration stops.
func (g *Group) Adopt(child *Group, deferActivation bool) (func(), error) {
	e := &entry{start: child.Activate, close: child.Close, deferred: deferActivation}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return func() {}, net.ErrClosed
	}
	if g.entries == nil {
		g.entries = map[*entry]struct{}{}
	}
	g.entries[e] = struct{}{}
	remove := func() { g.mu.Lock(); delete(g.entries, e); g.mu.Unlock() }
	if g.active && !deferActivation {
		return remove, child.Activate()
	}
	return remove, nil
}
func (g *Group) Activate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	if g.active {
		return nil
	}
	g.active = true
	var errs []error
	for e := range g.entries {
		if !e.deferred {
			e.startErr = e.start()
			errs = append(errs, e.startErr)
		}
	}
	return errors.Join(errs...)
}
func (g *Group) Close() error {
	g.mu.Lock()
	if g.closed {
		done := g.done
		g.mu.Unlock()
		<-done
		return g.err
	}
	g.closed = true
	g.done = make(chan struct{})
	entries := g.entries
	g.entries = nil
	g.shared = nil
	g.mu.Unlock()
	var errs []error
	for e := range entries {
		errs = append(errs, e.close())
	}
	g.mu.Lock()
	g.err = errors.Join(errs...)
	close(g.done)
	g.mu.Unlock()
	return g.err
}
