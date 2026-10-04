package kcptun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/internal/session"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/smux"
)

type Server struct {
	config    Config
	block     kcp.BlockCrypt
	mu        sync.Mutex
	closeMu   sync.Mutex
	closed    bool
	listeners []*kcp.Listener
	serveWG   sync.WaitGroup
	sessions  *session.Group
}

func NewServer(config Config) *Server {
	return NewServerContext(context.Background(), config)
}

func NewServerContext(ctx context.Context, config Config) *Server {
	config.FillDefaults()
	block := config.NewBlock()

	return &Server{
		config:   config,
		block:    block,
		sessions: session.New(ctx),
	}
}

func (s *Server) Serve(pc net.PacketConn, handler func(net.Conn)) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	lis, err := kcp.ServeConn(s.block, s.config.DataShard, s.config.ParityShard, pc)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.listeners = append(s.listeners, lis)
	s.serveWG.Add(1)
	s.mu.Unlock()
	defer s.serveWG.Done()
	defer lis.Close()
	_ = lis.SetDSCP(s.config.DSCP)
	_ = lis.SetReadBuffer(s.config.SockBuf)
	_ = lis.SetWriteBuffer(s.config.SockBuf)
	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			return err
		}
		owned, err := s.sessions.Begin(func() error {
			err := conn.Close()
			if errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		})
		if err != nil {
			continue
		}
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(s.config.NoDelay, s.config.Interval, s.config.Resend, s.config.NoCongestion)
		conn.SetMtu(s.config.MTU)
		conn.SetWindowSize(s.config.SndWnd, s.config.RcvWnd)
		conn.SetACKNoDelay(s.config.AckNodelay)
		conn.SetRateLimit(uint32(s.config.RateLimit))

		var netConn net.Conn = conn
		if !s.config.NoComp {
			netConn = NewCompStream(netConn)
		}

		owned.Run(func() {
			// stream multiplex
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = s.config.SmuxVer
			smuxConfig.MaxReceiveBuffer = s.config.SmuxBuf
			smuxConfig.MaxStreamBuffer = s.config.StreamBuf
			smuxConfig.MaxFrameSize = s.config.FrameSize
			smuxConfig.KeepAliveInterval = time.Duration(s.config.KeepAlive) * time.Second
			if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
				smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
			}

			mux, err := smux.Server(netConn, smuxConfig)
			if err != nil {
				_ = netConn.Close()
				return
			}
			defer mux.Close()

			for {
				stream, err := mux.AcceptStream()
				if err != nil {
					return
				}
				owned.Go(func() { handler(stream) })
			}
		})

	}
}

func (s *Server) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	s.closed = true
	listeners := append([]*kcp.Listener{}, s.listeners...)
	s.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		if err := l.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			errs = append(errs, err)
		}
	}
	s.serveWG.Wait()
	return errors.Join(append(errs, s.sessions.Close())...)
}
