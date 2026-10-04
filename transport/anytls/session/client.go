package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/skiplist"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc
	idleDone  <-chan struct{}

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex
	closed       bool
	creating     sync.WaitGroup
	reaping      sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error

	padding *atomic.Pointer[padding.PaddingFactory]

	clientMetadata     string
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool
}

func NewClient(ctx context.Context, dialOut util.DialOutFunc, _padding *atomic.Pointer[padding.PaddingFactory], clientMetadata string, idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, disableReuse bool) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		clientMetadata:     clientMetadata,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		disableReuse:       disableReuse,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	if !c.disableReuse {
		c.idleDone = util.StartRoutine(c.die, idleSessionCheckInterval, c.idleCleanup)
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	c.sessionsLock.Lock()
	if c.closed || c.die.Err() != nil {
		c.sessionsLock.Unlock()
		return nil, io.ErrClosedPipe
	}
	c.creating.Add(1)
	c.sessionsLock.Unlock()
	defer c.creating.Done()

	var session *Session
	var stream *Stream
	var err error

	if !c.disableReuse {
		session = c.getIdleSession()
	}
	if session == nil {
		session, err = c.createSession(ctx)
	}
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err = session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %w", errors.Join(err, session.Close()))
	}

	stream.setDieHook(func() {
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			if c.disableReuse {
				session.close()
				return
			}

			select {
			case <-c.die.Done():
				// Now client has been closed
				session.close()
			default:
				c.idleSessionLock.Lock()
				if !session.IsClosed() && c.die.Err() == nil {
					session.idleSince = time.Now()
					c.idleSession.Insert(math.MaxUint64-session.seq, session)
				}
				c.idleSessionLock.Unlock()
			}
		}
	})
	if c.die.Err() != nil || session.IsClosed() {
		return nil, errors.Join(io.ErrClosedPipe, session.Close())
	}

	return stream, nil
}

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	if !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		idle = it.Value()
		c.idleSession.Remove(it.Key())
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.die, cancel)
	if c.die.Err() != nil {
		cancel()
	}
	ctx, release := forwarding.SharedDialContext(ctx)
	defer release()
	underlying, err := c.dialOut(ctx)
	if underlying == nil {
		stop()
		cancel()
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.reaping.Add(1)
	closed := c.closed || c.die.Err() != nil
	c.sessionsLock.Unlock()
	go func() {
		defer c.reaping.Done()
		<-session.done
		stop()
		cancel()
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		if session.closeErr == nil {
			delete(c.sessions, session.seq)
		} else {
			// Preserve the failed session and its underlying handle. Further
			// creation is unsafe; Client.Close will return the retained error.
			c.closed = true
			c.dieCancel()
		}
		c.sessionsLock.Unlock()
	}()
	if closed || err != nil || ctx.Err() != nil {
		if err == nil {
			err = ctx.Err()
			if closed || err == nil {
				err = io.ErrClosedPipe
			}
		}
		return nil, errors.Join(err, session.Close())
	}

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.sessionsLock.Lock()
		c.closed = true
		c.dieCancel()
		for _, session := range c.sessions {
			session.close()
		}
		c.sessionsLock.Unlock()
		if c.idleDone != nil {
			<-c.idleDone
		}
		// A dialer may ignore cancellation and return a connection late. Its
		// creator closes that connection before releasing this registration.
		c.creating.Wait()
		c.reaping.Wait()
		c.sessionsLock.Lock()
		sessions := make([]*Session, 0, len(c.sessions))
		for _, session := range c.sessions {
			sessions = append(sessions, session)
		}
		c.sessionsLock.Unlock()
		var failures []error
		for _, session := range sessions {
			if err := session.Close(); err != nil {
				failures = append(failures, err)
			}
		}
		c.closeErr = errors.Join(failures...)
	})
	return c.closeErr
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0

	c.idleSessionLock.Lock()
	sessionToClose := make([]*Session, 0, c.idleSession.Len())

	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
