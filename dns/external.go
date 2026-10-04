package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

var ErrExternalIngressStopped = errors.New("external DNS ingress is stopped")

type externalConfig struct {
	addr    string
	lc      C.InboundListenConfig
	service resolver.Service
}

type externalRun struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	accepting bool
	active    int
	done      chan struct{}
}

func newExternalRun(parent context.Context) *externalRun {
	ctx, cancel := context.WithCancel(parent)
	return &externalRun{ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

func (r *externalRun) begin(parent context.Context) (context.Context, func(), error) {
	if r == nil {
		return parent, func() {}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.accepting || r.ctx.Err() != nil {
		return nil, nil, ErrExternalIngressStopped
	}
	r.active++
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(r.ctx, cancel)
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stop()
			cancel()
			r.mu.Lock()
			defer r.mu.Unlock()
			r.active--
			if !r.accepting && r.active == 0 {
				close(r.done)
			}
		})
	}, nil
}

func (r *externalRun) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.accepting {
		// A partially bound run never became accepting.
		select {
		case <-r.done:
		default:
			if r.active == 0 {
				close(r.done)
			}
		}
		r.cancel()
		return
	}
	r.accepting = false
	r.cancel()
	if r.active == 0 {
		close(r.done)
	}
}

type externalIngress struct {
	opMu    sync.Mutex
	mu      sync.Mutex
	managed bool
	run     *externalRun
	server  *Server
	config  externalConfig
}

var external externalIngress

func (e *externalIngress) isManaged() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.managed
}

// SetExternalIngressManaged opts an embedding application into explicit
// external DNS/DoH start/stop. Call before applying configuration. Changing the
// policy cannot discard a live or incompletely cleaned operation.
func SetExternalIngressManaged(managed bool) error {
	external.opMu.Lock()
	defer external.opMu.Unlock()
	external.mu.Lock()
	defer external.mu.Unlock()
	if external.run != nil {
		return errors.New("cannot change external DNS policy with an existing run")
	}
	external.managed = managed
	return nil
}

// StartExternalIngress binds configured DNS UDP/TCP and admits controller DoH
// queries. A failed bind rolls back acquired resources; failed rollback remains
// owned and blocks another Start until Stop confirms cleanup.
func StartExternalIngress(parent context.Context) error {
	external.opMu.Lock()
	defer external.opMu.Unlock()
	return external.start(parent)
}

func (e *externalIngress) start(parent context.Context) error {
	e.mu.Lock()
	if e.run != nil {
		e.mu.Unlock()
		return errors.New("external DNS run already exists; stop it before starting")
	}
	if err := parent.Err(); err != nil {
		e.mu.Unlock()
		return err
	}
	run := newExternalRun(parent)
	s := &Server{service: e.config.service, run: run}
	e.run, e.server = run, s
	e.mu.Unlock()
	err := s.bind(run.ctx, e.config)
	if err == nil {
		err = run.ctx.Err()
	}
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), externalCleanupTimeout)
		defer cancel()
		return errors.Join(err, e.stop(ctx))
	}
	run.mu.Lock()
	run.accepting = true
	run.mu.Unlock()
	return nil
}

// StopExternalIngress immediately rejects new queries, cancels this run's
// waiters and waits for handlers and sockets. Resolver shared queries have
// their own bounded context and are intentionally not cancelled by one client.
func StopExternalIngress(ctx context.Context) error {
	// Cancellation precedes the operation lock: a Start may be binding.
	external.mu.Lock()
	if external.run != nil {
		external.run.cancel()
	}
	external.mu.Unlock()
	external.opMu.Lock()
	defer external.opMu.Unlock()
	return external.stop(ctx)
}

func (e *externalIngress) stop(ctx context.Context) error {
	e.mu.Lock()
	run, s := e.run, e.server
	e.mu.Unlock()
	if run == nil {
		return nil
	}
	run.stop()
	err := s.stop(ctx)
	select {
	case <-run.done:
	case <-ctx.Done():
		err = errors.Join(err, fmt.Errorf("wait for external DNS queries: %w", ctx.Err()))
	}
	if err == nil {
		e.mu.Lock()
		e.run, e.server = nil, nil
		e.mu.Unlock()
	}
	return err
}

// BeginExternalQuery is used by controller DoH only. Management API and
// resolver calls do not pass through this gate. The caller must defer finish
// through the final response write and check ctx before publishing a result.
func BeginExternalQuery(parent context.Context) (ctx context.Context, finish func(), err error) {
	external.mu.Lock()
	run, managed := external.run, external.managed
	external.mu.Unlock()
	if !managed {
		return parent, func() {}, nil
	}
	if run == nil {
		return nil, nil, ErrExternalIngressStopped
	}
	return run.begin(parent)
}
