package inbound

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
)

type SocksOption struct {
	BaseOption
	Users          AuthUsers     `inbound:"users,omitempty"`
	UDP            bool          `inbound:"udp,omitempty"`
	Certificate    string        `inbound:"certificate,omitempty"`
	PrivateKey     string        `inbound:"private-key,omitempty"`
	ClientAuthType string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string        `inbound:"client-auth-cert,omitempty"`
	EchKey         string        `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig `inbound:"reality-config,omitempty"`
}

func (o SocksOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Socks struct {
	*Base
	config *SocksOption
	udp    bool
	stl    []*socks.Listener
	sul    []*socks.UDPListener
}

func NewSocks(options *SocksOption) (*Socks, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Socks{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil
}

// Config implements constant.InboundListener
func (s *Socks) Config() C.InboundConfig {
	return s.config
}

// Close implements constant.InboundListener
func (s *Socks) Close() error {
	var err error
	var errs []error
	s.stl, err = closeListeners(s.stl)
	if err != nil {
		errs = append(errs, err)
	}
	s.sul, err = closeListeners(s.sul)
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Address implements constant.InboundListener
func (s *Socks) Address() string {
	var addrList []string
	for _, l := range s.stl {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *Socks) Listen(tunnel C.Tunnel) (err error) {
	if len(s.stl) != 0 || len(s.sul) != 0 {
		return errors.New("listener is already running")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	lc := s.ListenConfig()
	for _, addr := range strings.Split(s.RawAddress(), ",") {
		config := LC.AuthServer{
			Enable:         true,
			Listen:         addr,
			AuthStore:      s.config.Users.GetAuthStore(),
			Certificate:    s.config.Certificate,
			PrivateKey:     s.config.PrivateKey,
			ClientAuthType: s.config.ClientAuthType,
			ClientAuthCert: s.config.ClientAuthCert,
			EchKey:         s.config.EchKey,
			RealityConfig:  s.config.RealityConfig.Build(),
		}
		stl, err := socks.NewWithConfig(config, lc, tunnel, s.Additions()...)
		if err != nil {
			return err
		}
		s.stl = append(s.stl, stl)
		if s.udp {
			sul, err := socks.NewUDPWithConfig(config, lc, tunnel, s.Additions()...)
			if err != nil {
				return err
			}
			s.sul = append(s.sul, sul)
		}
	}

	log.Infoln("SOCKS[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

var _ C.InboundListener = (*Socks)(nil)
