package tuic

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/internal/session"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"
	v4 "github.com/metacubex/mihomo/transport/tuic/v4"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type ServerOption struct {
	Context context.Context
	// AsyncTCP preserves TUIC v4's response-before-relay ordering while
	// retaining ownership of the asynchronous application handler.
	AsyncTCP    bool
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Tokens                [][32]byte          // V4 special
	Users                 map[[16]byte]string // V5 special
	CongestionController  string
	AuthenticationTimeout time.Duration
	MaxUdpRelayPacketSize int
	CWND                  int
	BBRProfile            string
}

type Server struct {
	*ServerOption
	optionV4 *v4.ServerOption
	optionV5 *v5.ServerOption
	listener *quic.EarlyListener
	mu       sync.Mutex
	closed   bool
	serveWG  sync.WaitGroup
	sessions *session.Group
}

func (s *Server) Serve() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.serveWG.Add(1)
	s.mu.Unlock()
	defer s.serveWG.Done()
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		owned, err := s.sessions.Begin(func() error { return conn.CloseWithError(0, "server stopped") })
		if err != nil {
			continue
		}
		common.SetCongestionController(conn, s.CongestionController, s.CWND, s.BBRProfile)
		h := &serverHandler{
			Server:   s,
			quicConn: conn,
			uuid:     utils.NewUUIDV4(),
			session:  owned,
		}
		if h.optionV4 != nil {
			option := *h.optionV4
			if s.AsyncTCP {
				option.HandleTcpFn = h.handleTCPAsync
			}
			h.v4Handler = v4.NewServerHandler(&option, conn, h.uuid)
		}
		if h.optionV5 != nil {
			option := *h.optionV5
			if s.AsyncTCP {
				option.HandleTcpFn = h.handleTCPAsync
			}
			h.v5Handler = v5.NewServerHandler(&option, conn, h.uuid)
		}
		owned.Run(h.handle)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	err := s.listener.Close()
	s.serveWG.Wait()
	return errors.Join(err, s.sessions.Close())
}

type serverHandler struct {
	*Server
	quicConn *quic.Conn
	uuid     uuid.UUID
	session  *session.Session

	v4Handler types.ServerHandler
	v5Handler types.ServerHandler
}

func (s *serverHandler) handleTCPAsync(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error {
	s.session.Go(func() {
		if err := s.HandleTcpFn(conn, addr, additions...); err != nil {
			_ = conn.Close()
		}
	})
	return nil
}

func (s *serverHandler) handle() {
	s.session.Go(func() {
		_ = s.handleUniStream()
	})
	s.session.Go(func() {
		_ = s.handleStream()
	})
	s.session.Go(func() {
		_ = s.handleMessage()
	})

	select {
	case <-s.quicConn.HandshakeComplete(): // this chan maybe not closed if handshake never complete
	case <-time.After(s.quicConn.Config().HandshakeIdleTimeout): // HandshakeIdleTimeout in real conn.Config() never be zero
	case <-s.quicConn.Context().Done():
	}

	timer := time.NewTimer(s.AuthenticationTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.quicConn.Context().Done():
	}
	if s.v4Handler != nil {
		if s.v4Handler.AuthOk() {
			return
		}
	}

	if s.v5Handler != nil {
		if s.v5Handler.AuthOk() {
			return
		}
	}

	if s.v4Handler != nil {
		s.v4Handler.HandleTimeout()
	}

	if s.v5Handler != nil {
		s.v5Handler.HandleTimeout()
	}
}

func (s *serverHandler) handleMessage() (err error) {
	for {
		var message []byte
		message, err = s.quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		s.session.Go(func() {
			_ = s.dispatchMessage(message)
		})
	}
}

func (s *serverHandler) dispatchMessage(message []byte) error {
	if len(message) > 0 {
		switch message[0] {
		case v4.VER:
			if s.v4Handler != nil {
				return s.v4Handler.HandleMessage(message)
			}
		case v5.VER:
			if s.v5Handler != nil {
				return s.v5Handler.HandleMessage(message)
			}
		}
	}
	return nil
}

func (s *serverHandler) handleStream() (err error) {
	for {
		var quicStream *quic.Stream
		quicStream, err = s.quicConn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		s.session.Go(func() {
			_ = s.dispatchStream(quicStream)
		})
	}
}

func (s *serverHandler) dispatchStream(quicStream *quic.Stream) error {
	stream := types.NewQuicStreamConn(quicStream, s.quicConn.LocalAddr(), s.quicConn.RemoteAddr(), nil)
	conn := N.NewBufferedConn(stream)
	verBytes, err := conn.Peek(1)
	if err != nil {
		_ = conn.Close()
		return err
	}
	switch verBytes[0] {
	case v4.VER:
		if s.v4Handler != nil {
			return s.v4Handler.HandleStream(conn)
		}
	case v5.VER:
		if s.v5Handler != nil {
			return s.v5Handler.HandleStream(conn)
		}
	}
	return conn.Close()
}

func (s *serverHandler) handleUniStream() (err error) {
	for {
		var stream *quic.ReceiveStream
		stream, err = s.quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		s.session.Go(func() {
			_ = s.dispatchUniStream(stream)
		})
	}
}

func (s *serverHandler) dispatchUniStream(stream *quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	reader := bufio.NewReader(stream)
	verBytes, err := reader.Peek(1)
	if err != nil {
		return err
	}
	switch verBytes[0] {
	case v4.VER:
		if s.v4Handler != nil {
			return s.v4Handler.HandleUniStream(reader)
		}
	case v5.VER:
		if s.v5Handler != nil {
			return s.v5Handler.HandleUniStream(reader)
		}
	}
	return nil
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	listener, err := quic.ListenEarly(pc, option.TlsConfig, option.QuicConfig)
	if err != nil {
		return nil, err
	}
	server := &Server{
		ServerOption: option,
		listener:     listener,
		sessions:     session.New(option.Context),
	}
	if len(option.Tokens) > 0 {
		server.optionV4 = &v4.ServerOption{
			HandleTcpFn:           option.HandleTcpFn,
			HandleUdpFn:           option.HandleUdpFn,
			Tokens:                option.Tokens,
			MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
		}
	}
	if len(option.Users) > 0 {
		maxUdpRelayPacketSize := option.MaxUdpRelayPacketSize
		if maxUdpRelayPacketSize > MaxFragSizeV5 {
			maxUdpRelayPacketSize = MaxFragSizeV5
		}
		server.optionV5 = &v5.ServerOption{
			HandleTcpFn:           option.HandleTcpFn,
			HandleUdpFn:           option.HandleUdpFn,
			Users:                 option.Users,
			MaxUdpRelayPacketSize: maxUdpRelayPacketSize,
		}
	}
	return server, nil
}
