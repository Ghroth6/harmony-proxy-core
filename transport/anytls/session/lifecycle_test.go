package session

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

type lifecycleConn struct {
	net.Conn
	readStarted  chan struct{}
	readExited   chan struct{}
	readRelease  <-chan struct{}
	closeStarted chan struct{}
	closeRelease <-chan struct{}
	closeErr     error
	readOnce     sync.Once
	readExitOnce sync.Once
	closeOnce    sync.Once
	closes       atomic.Int32
}

func (c *lifecycleConn) Read(b []byte) (int, error) {
	c.readOnce.Do(func() {
		if c.readStarted != nil {
			close(c.readStarted)
		}
	})
	n, err := c.Conn.Read(b)
	if err != nil {
		c.readExitOnce.Do(func() {
			if c.readExited != nil {
				close(c.readExited)
			}
		})
		if c.readRelease != nil {
			<-c.readRelease
		}
	}
	return n, err
}

func (c *lifecycleConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.closeStarted != nil {
			close(c.closeStarted)
		}
	})
	if c.closeRelease != nil {
		<-c.closeRelease
	}
	return errors.Join(err, c.closeErr)
}

func lifecyclePadding() *atomic.Pointer[padding.PaddingFactory] {
	pad := new(atomic.Pointer[padding.PaddingFactory])
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, pad)
	return pad
}

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle operation did not progress")
	}
}

func lifecycleResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle operation did not complete")
		return nil
	}
}

func lifecycleBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("close returned before actual work completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestSessionCloseWaitsForReceiverAndAllConcurrentClosers(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	release := make(chan struct{})
	c := &lifecycleConn{Conn: left, readStarted: make(chan struct{}), readExited: make(chan struct{}), readRelease: release}
	s := NewClientSession(c, lifecyclePadding(), "test")
	s.Run()
	lifecycleWait(t, c.readStarted)
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- s.Close() }()
	lifecycleWait(t, c.readExited)
	go func() { second <- s.Close() }()
	lifecycleBlocked(t, first)
	lifecycleBlocked(t, second)
	close(release)
	if err := lifecycleResult(t, first); err != nil {
		t.Fatal(err)
	}
	if err := lifecycleResult(t, second); err != nil {
		t.Fatal(err)
	}
	if c.closes.Load() != 1 {
		t.Fatalf("physical Close count = %d", c.closes.Load())
	}
}

func TestSessionCloseRetainsPhysicalFailureUntilItActuallyReturns(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	release := make(chan struct{})
	want := errors.New("physical close failed")
	c := &lifecycleConn{Conn: left, closeStarted: make(chan struct{}), closeRelease: release, closeErr: errors.Join(io.ErrClosedPipe, want)}
	s := NewClientSession(c, lifecyclePadding(), "test")
	s.Run()
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	lifecycleWait(t, c.closeStarted)
	lifecycleBlocked(t, done)
	close(release)
	if err := lifecycleResult(t, done); !errors.Is(err, want) {
		t.Fatalf("Close = %v", err)
	}
	if err := s.Close(); !errors.Is(err, want) {
		t.Fatalf("repeated Close = %v", err)
	}
	if c.closes.Load() != 1 {
		t.Fatalf("physical Close count = %d", c.closes.Load())
	}
}

func TestSessionRunCannotStartAfterClose(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c := &lifecycleConn{Conn: left, readStarted: make(chan struct{})}
	s := NewClientSession(c, lifecyclePadding(), "test")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.Run()
	select {
	case <-c.readStarted:
		t.Fatal("receiver started after Close returned")
	default:
	}
	if _, err := s.OpenStream(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("late OpenStream = %v", err)
	}
}

func TestSessionCloseUnblocksUnreadStreamPayload(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	s := NewClientSession(left, lifecyclePadding(), "test")
	s.Run()
	if _, err := s.OpenStream(); err != nil {
		t.Fatal(err)
	}
	pushed := make(chan error, 1)
	go func() {
		f := newFrame(cmdPSH, 1)
		f.data = []byte("unread payload")
		pushed <- lifecycleWriteFrame(right, f)
	}()
	if err := lifecycleResult(t, pushed); err != nil {
		t.Fatal(err)
	}
	// Receiving the complete physical frame can leave recvLoop blocked in the
	// stream pipe rather than the socket. Closing the socket alone cannot join it.
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	if err := lifecycleResult(t, done); err != nil {
		t.Fatal(err)
	}
}

// Install the SYNACK timer through actual OpenStream calls, not its helper.
func lifecycleAwaitingSYNACK(t *testing.T) (*Session, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	s := NewClientSession(left, lifecyclePadding(), "test")
	s.Run()
	// The server settings frame goes through recvLoop and changes the actual
	// negotiated version before the second stream is opened.
	f := newFrame(cmdServerSettings, 0)
	f.data = []byte("v=2\n")
	written := make(chan error, 1)
	go func() { written <- lifecycleWriteFrame(right, f) }()
	if err := lifecycleResult(t, written); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.peerVersion.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.peerVersion.Load() < 2 {
		t.Fatal("server version was not negotiated")
	}
	go io.Copy(io.Discard, right)
	if _, err := s.OpenStream(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenStream(); err != nil {
		t.Fatal(err)
	}
	return s, right
}

func lifecycleWriteFrame(conn net.Conn, f frame) error {
	b := make([]byte, headerOverHeadSize+len(f.data))
	b[0] = f.cmd
	binary.BigEndian.PutUint32(b[1:5], f.sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(f.data)))
	copy(b[7:], f.data)
	_, err := conn.Write(b)
	return err
}

func TestSessionCloseCancelsSYNACKWatcher(t *testing.T) {
	s, right := lifecycleAwaitingSYNACK(t)
	defer right.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.synDoneLock.Lock()
	defer s.synDoneLock.Unlock()
	if s.synDone != nil {
		t.Fatal("Close retained its SYNACK watcher")
	}
}

func TestSessionSYNACKTimeoutClosesWithoutJoiningItself(t *testing.T) {
	s, right := lifecycleAwaitingSYNACK(t)
	defer right.Close()
	select {
	case <-s.die:
	case <-time.After(4 * time.Second):
		t.Fatal("SYNACK timeout did not close session")
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	if err := lifecycleResult(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestClientCloseCancelsAndWaitsForLateDialCleanup(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "successful-cleanup"
		if failed {
			name = "failed-cleanup"
		}
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			dialStarted, cancelled, dialRelease, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var want error
			if failed {
				want = errors.New("late dial close failed")
			}
			physical := &lifecycleConn{Conn: left, closeStarted: make(chan struct{}), closeRelease: closeRelease, closeErr: want}
			c := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
				close(dialStarted)
				<-ctx.Done()
				close(cancelled)
				<-dialRelease
				return physical, nil // Simulate a dialer that returns success after cancellation.
			}, lifecyclePadding(), "test", time.Hour, time.Hour, 0, false)
			created, closed := make(chan error, 1), make(chan error, 1)
			go func() {
				conn, err := c.CreateStream(context.Background())
				if conn != nil {
					err = errors.New("late connection escaped")
				}
				created <- err
			}()
			lifecycleWait(t, dialStarted)
			go func() { closed <- c.Close() }()
			lifecycleWait(t, cancelled)
			lifecycleBlocked(t, closed)
			close(dialRelease)
			lifecycleWait(t, physical.closeStarted)
			lifecycleBlocked(t, closed)
			close(closeRelease)
			if err := lifecycleResult(t, created); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("CreateStream = %v", err)
			}
			if err := lifecycleResult(t, closed); !errors.Is(err, want) {
				t.Fatalf("Close = %v, want %v", err, want)
			}
			if err := c.Close(); !errors.Is(err, want) {
				t.Fatalf("repeated Close = %v", err)
			}
			if physical.closes.Load() != 1 {
				t.Fatalf("physical Close count = %d", physical.closes.Load())
			}
			if _, err := c.CreateStream(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("late CreateStream = %v", err)
			}
			c.sessionsLock.Lock()
			defer c.sessionsLock.Unlock()
			if failed && len(c.sessions) != 1 {
				t.Fatal("failed cleanup lost physical handle ownership")
			}
			if !failed && len(c.sessions) != 0 {
				t.Fatal("successful cleanup retained historical session")
			}
		})
	}
}

func TestClientRetainsSpontaneousSessionCloseFailure(t *testing.T) {
	left, right := net.Pipe()
	want := errors.New("peer disconnected but local close failed")
	physical := &lifecycleConn{Conn: left, closeErr: want, closeStarted: make(chan struct{})}
	c := NewClient(context.Background(), func(context.Context) (net.Conn, error) { return physical, nil }, lifecyclePadding(), "test", time.Hour, time.Hour, 0, false)
	if _, err := c.CreateStream(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = right.Close()
	lifecycleWait(t, physical.closeStarted)
	lifecycleWait(t, c.die.Done()) // Failure closes admission, not just the idle pool.
	if err := c.Close(); !errors.Is(err, want) {
		t.Fatalf("Close forgot earlier failure: %v", err)
	}
	if physical.closes.Load() != 1 {
		t.Fatalf("physical Close count = %d", physical.closes.Load())
	}
}

func TestClientRemoteFINWithReuseDisabledDoesNotSelfJoin(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	physical := &lifecycleConn{Conn: left, closeStarted: make(chan struct{})}
	c := NewClient(context.Background(), func(context.Context) (net.Conn, error) { return physical, nil }, lifecyclePadding(), "test", time.Hour, time.Hour, 0, true)
	stream, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycleWriteFrame(right, newFrame(cmdFIN, 1)); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, physical.closeStarted)
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed stream Read = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	if err := lifecycleResult(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestClientAdoptsFailedDialConnectionUntilCleanupCompletes(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	closeFailure, dialFailure := errors.New("cleanup failed"), errors.New("handshake failed")
	physical := &lifecycleConn{Conn: left, closeErr: closeFailure}
	c := NewClient(context.Background(), func(context.Context) (net.Conn, error) { return physical, dialFailure }, lifecyclePadding(), "test", time.Hour, time.Hour, 0, false)
	if _, err := c.CreateStream(context.Background()); !errors.Is(err, dialFailure) || !errors.Is(err, closeFailure) {
		t.Fatalf("CreateStream = %v", err)
	}
	if err := c.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("Close = %v", err)
	}
	if physical.closes.Load() != 1 {
		t.Fatalf("physical Close count = %d", physical.closes.Load())
	}
}
