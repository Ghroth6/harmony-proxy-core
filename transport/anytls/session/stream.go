package session

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/pipe"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce   sync.Once
	stateLock sync.Mutex
	dieHook   func()
	dieErr    error

	reportOnce sync.Once
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if closedErr := s.closedError(); n == 0 && closedErr != nil {
		err = closedErr
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if err := s.closedError(); err != nil {
		return 0, err
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		s.stateLock.Lock()
		s.dieErr = net.ErrClosed
		s.writeDeadline.Set(time.Time{})
		s.pipeR.Close()
		s.stateLock.Unlock()
		once = true
	})
	if once {
		s.callDieHook()
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.stateLock.Lock()
		s.dieErr = err
		s.writeDeadline.Set(time.Time{})
		s.pipeR.Close()
		s.stateLock.Unlock()
		once = true
	})
	if once {
		err := s.sess.streamClosed(s.id)
		s.callDieHook()
		return err
	} else {
		return s.closedError()
	}
}

func (s *Stream) closedError() error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()
	return s.dieErr
}

func (s *Stream) setDieHook(hook func()) {
	s.stateLock.Lock()
	s.dieHook = hook
	closed := s.dieErr != nil
	s.stateLock.Unlock()
	if closed {
		s.callDieHook()
	}
}

func (s *Stream) callDieHook() {
	s.stateLock.Lock()
	hook := s.dieHook
	s.dieHook = nil
	s.stateLock.Unlock()
	if hook != nil {
		hook()
	}
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()
	if s.dieErr != nil {
		return s.dieErr
	}
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion.Load() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion.Load() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
