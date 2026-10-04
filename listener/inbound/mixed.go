package inbound

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
)

type MixedOption struct {
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

func (o MixedOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Mixed struct {
	*Base
	config *MixedOption
	l      []*mixed.Listener
	lUDP   []*socks.UDPListener
	udp    bool
}

func NewMixed(options *MixedOption) (*Mixed, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil
}

// Config implements constant.InboundListener
func (m *Mixed) Config() C.InboundConfig {
	return m.config
}

// Address implements constant.InboundListener
func (m *Mixed) Address() string {
	var addrList []string
	for _, l := range m.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (m *Mixed) Listen(tunnel C.Tunnel) (err error) {
	if len(m.l) != 0 || len(m.lUDP) != 0 {
		return errors.New("listener is already running")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, m.Close())
		}
	}()
	lc := m.ListenConfig()
	for _, addr := range strings.Split(m.RawAddress(), ",") {
		config := LC.AuthServer{
			Enable:         true,
			Listen:         addr,
			AuthStore:      m.config.Users.GetAuthStore(),
			Certificate:    m.config.Certificate,
			PrivateKey:     m.config.PrivateKey,
			ClientAuthType: m.config.ClientAuthType,
			ClientAuthCert: m.config.ClientAuthCert,
			EchKey:         m.config.EchKey,
			RealityConfig:  m.config.RealityConfig.Build(),
		}
		l, err := mixed.NewWithConfig(config, lc, tunnel, m.Additions()...)
		if err != nil {
			return err
		}
		m.l = append(m.l, l)
		if m.udp {
			lUDP, err := socks.NewUDPWithConfig(config, lc, tunnel, m.Additions()...)
			if err != nil {
				return err
			}
			m.lUDP = append(m.lUDP, lUDP)
		}
	}
	log.Infoln("Mixed(http+socks)[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// Close implements constant.InboundListener
func (m *Mixed) Close() error {
	var err error
	var errs []error
	m.l, err = closeListeners(m.l)
	if err != nil {
		errs = append(errs, err)
	}
	m.lUDP, err = closeListeners(m.lUDP)
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

var _ C.InboundListener = (*Mixed)(nil)
