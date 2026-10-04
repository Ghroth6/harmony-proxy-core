// Package session owns accepted multiplexed protocol sessions. Listener close
// ends admission; each session closes its transport and joins all registered
// protocol work before releasing its forwarding completion lease.
package session

import (
	"context"
	"errors"
	"sync"

	"github.com/metacubex/mihomo/component/forwarding"
)

type Group struct {
	mu       sync.Mutex
	ctx      context.Context
	closed   bool
	sessions map[*Session]struct{}
	errors   []error
}
type Session struct {
	group  *Group
	wg     sync.WaitGroup
	close  func() error
	finish func()
	done   chan struct{}
}

func New(ctx context.Context) *Group {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Group{ctx: ctx, sessions: make(map[*Session]struct{})}
}

func (g *Group) Begin(close func() error) (*Session, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx, finish, err := forwarding.Acquire(g.ctx)
	if err == nil && g.closed {
		finish()
		err = forwarding.ErrStopped
	}
	if err != nil {
		if closeErr := close(); closeErr != nil {
			g.errors = append(g.errors, closeErr)
		}
		return nil, err
	}
	var once sync.Once
	var closeErr error
	ownedClose := forwarding.Cleanup(ctx, func() error { once.Do(func() { closeErr = close() }); return closeErr })
	s := &Session{group: g, close: ownedClose, finish: finish, done: make(chan struct{})}
	g.sessions[s] = struct{}{}
	return s, nil
}

// Run starts one root task. Its children must use Go before their parent
// returns, so Wait cannot miss a task added after the count reaches zero.
func (s *Session) Run(f func()) {
	s.Go(f)
	go func() {
		s.wg.Wait()
		err := s.close()
		s.group.mu.Lock()
		if err == nil {
			delete(s.group.sessions, s)
		}
		s.group.mu.Unlock()
		s.finish()
		close(s.done)
	}()
}
func (s *Session) Go(f func()) {
	s.wg.Add(1)
	go func() { defer s.wg.Done(); f() }()
}
func (s *Session) Done() <-chan struct{} { return s.done }

// Close initiates and confirms transport closes. It does not hide unfinished
// callbacks: their forwarding leases remain pending until Run has joined them.
func (g *Group) Close() error {
	g.mu.Lock()
	g.closed = true
	sessions := make([]*Session, 0, len(g.sessions))
	for s := range g.sessions {
		sessions = append(sessions, s)
	}
	errs := append([]error{}, g.errors...)
	g.mu.Unlock()
	for _, s := range sessions {
		errs = append(errs, s.close())
	}
	return errors.Join(errs...)
}
