package kcptun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/randv2"
	"github.com/metacubex/smux"
)

const Mode = "kcptun"

type DialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

type Client struct {
	once   sync.Once
	config Config
	block  kcp.BlockCrypt

	ctx    context.Context
	cancel context.CancelFunc

	numconn       uint16
	muxes         []timedSession
	rr            uint16
	connMu        sync.Mutex
	sessions      map[*smux.Session]struct{}
	scavengerDone sync.WaitGroup
	closing       sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error

	chScavenger chan timedSession
}

func NewClient(config Config) *Client {
	config.FillDefaults()
	block := config.NewBlock()

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config: config,
		block:  block,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (c *Client) Close() error {
	c.cancel()
	c.closeOnce.Do(func() {
		c.connMu.Lock()
		for session := range c.sessions {
			c.closeSessionLocked(session)
		}
		c.connMu.Unlock()
		c.scavengerDone.Wait()
		c.closing.Wait()
	})
	return c.closeErr
}

func (c *Client) closeSession(session *smux.Session) {
	c.connMu.Lock()
	c.closeSessionLocked(session)
	c.connMu.Unlock()
}

// Called with connMu held. IsClosed includes read/protocol failures; it does
// not prove that smux has closed the underlying KCP/UDP transport. Retain that
// Close until it returns, without holding up selection or another close.
func (c *Client) closeSessionLocked(session *smux.Session) {
	if _, owned := c.sessions[session]; !owned {
		return
	}
	delete(c.sessions, session)
	c.closing.Add(1)
	go func() {
		defer c.closing.Done()
		err := session.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			c.connMu.Lock()
			c.closeErr = errors.Join(c.closeErr, err)
			c.connMu.Unlock()
		}
	}()
}

func (c *Client) createConn(ctx context.Context, dial DialFn) (*smux.Session, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	ctx, release := forwarding.SharedDialContext(ctx)
	defer release()
	conn, addr, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	config := c.config
	convid := randv2.Uint32()
	kcpconn, err := kcp.NewConn4(convid, addr, c.block, config.DataShard, config.ParityShard, true, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)
	kcpconn.SetRateLimit(uint32(config.RateLimit))

	_ = kcpconn.SetDSCP(config.DSCP)
	_ = kcpconn.SetReadBuffer(config.SockBuf)
	_ = kcpconn.SetWriteBuffer(config.SockBuf)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.MaxFrameSize = config.FrameSize
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
		smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
	}

	if err := smux.VerifyConfig(smuxConfig); err != nil {
		_ = kcpconn.Close()
		return nil, err
	}

	var netConn net.Conn = kcpconn
	if !config.NoComp {
		netConn = NewCompStream(netConn)
	}
	// stream multiplex
	return smux.Client(netConn, smuxConfig)
}

func (c *Client) OpenStream(ctx context.Context, dial DialFn) (*smux.Stream, error) {
	session, err := c.getSession(ctx, dial)
	if err != nil {
		return nil, err
	}
	// Opening a stream can perform I/O. Close must retain access to connMu
	// and the session so it can interrupt that I/O.
	return session.OpenStream()
}

func (c *Client) getSession(ctx context.Context, dial DialFn) (*smux.Session, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	c.once.Do(func() {
		// start scavenger if autoexpire is set
		c.chScavenger = make(chan timedSession, 128)
		if c.config.AutoExpire > 0 {
			c.scavengerDone.Add(1)
			go func() { defer c.scavengerDone.Done(); scavenger(c.ctx, c.chScavenger, &c.config, c.closeSession) }()
		}

		c.numconn = uint16(c.config.Conn)
		c.muxes = make([]timedSession, c.config.Conn)
		c.rr = uint16(0)
		c.sessions = make(map[*smux.Session]struct{})
	})
	idx := c.rr % c.numconn

	// do auto expiration && reconnection
	if c.muxes[idx].session == nil || c.muxes[idx].session.IsClosed() ||
		(c.config.AutoExpire > 0 && time.Now().After(c.muxes[idx].expiryDate)) {
		var err error
		c.muxes[idx].session, err = c.createConn(ctx, dial)
		if err != nil {
			return nil, err
		}
		for session := range c.sessions {
			if session.IsClosed() {
				c.closeSessionLocked(session)
			}
		}
		c.sessions[c.muxes[idx].session] = struct{}{}
		if c.ctx.Err() != nil {
			c.closeSessionLocked(c.muxes[idx].session)
			return nil, net.ErrClosed
		}
		c.muxes[idx].expiryDate = time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
		if c.config.AutoExpire > 0 { // only when autoexpire set
			select {
			case c.chScavenger <- c.muxes[idx]:
			case <-c.ctx.Done():
				return nil, net.ErrClosed
			}
		}

	}
	c.rr++
	session := c.muxes[idx].session

	return session, nil
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

// scavenger goroutine is used to close expired sessions
func scavenger(ctx context.Context, ch chan timedSession, config *Config, closeSession func(*smux.Session)) {
	ticker := time.NewTicker(scavengePeriod * time.Second)
	defer ticker.Stop()
	var sessionList []timedSession
	for {
		select {
		case item := <-ch:
			sessionList = append(sessionList, timedSession{
				item.session,
				item.expiryDate.Add(time.Duration(config.ScavengeTTL) * time.Second)})
		case <-ticker.C:
			var newList []timedSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.IsClosed() {
					closeSession(s.session)
					log.Debugln("scavenger: retiring unusable session: %s", s.session.LocalAddr())
				} else if time.Now().After(s.expiryDate) {
					closeSession(s.session)
					log.Debugln("scavenger: retiring expired session: %s", s.session.LocalAddr())
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		case <-ctx.Done():
			return
		}
	}
}
