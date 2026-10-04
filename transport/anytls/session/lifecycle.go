package session

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// beginWork and close share the admission lock: no Add can race with the
// shutdown Wait after the last registered worker exits.
func (s *Session) beginWork() bool {
	s.lifecycleLock.Lock()
	defer s.lifecycleLock.Unlock()
	if s.IsClosed() {
		return false
	}
	s.workers.Add(1)
	return true
}

func (s *Session) close() {
	s.lifecycleLock.Lock()
	defer s.lifecycleLock.Unlock()
	if s.IsClosed() {
		return
	}
	close(s.die)
	go s.finishClose()
}

func (s *Session) finishClose() {
	s.synDoneLock.Lock()
	if s.synDone != nil {
		s.synDone()
		s.synDone = nil
	}
	s.synDoneLock.Unlock()

	s.streamLock.Lock()
	streams := s.streams
	s.streams = make(map[uint32]*Stream)
	s.streamLock.Unlock()
	for _, stream := range streams {
		stream.closeLocally()
	}
	// Close must wake physical I/O. A deadline additionally handles wrappers
	// whose failed Close leaves a receiver blocked; that failure is still kept.
	_ = s.conn.SetDeadline(time.Now())
	s.closeErr = normalizeCloseError(s.conn.Close())
	s.workers.Wait()
	close(s.done)
}

func (s *Session) watchSYNACK(timeout time.Duration) {
	s.synDoneLock.Lock()
	defer s.synDoneLock.Unlock()
	if s.synDone != nil {
		s.synDone()
		s.synDone = nil
	}
	if !s.beginWork() {
		return
	}
	cancel := make(chan struct{})
	var once sync.Once
	s.synDone = func() { once.Do(func() { close(cancel) }) }
	go func() {
		defer s.workers.Done()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-cancel:
		case <-s.die:
		case <-timer.C:
			s.close()
		}
	}()
}

// Some wrappers report an already closed transport after the peer/read loop
// initiates shutdown. Do not suppress an unknown sibling in a joined error.
func normalizeCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var failures []error
		for _, child := range joined.Unwrap() {
			if failure := normalizeCloseError(child); failure != nil {
				failures = append(failures, failure)
			}
		}
		return errors.Join(failures...)
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil && normalizeCloseError(child) == nil {
			return nil
		}
		return err
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}
