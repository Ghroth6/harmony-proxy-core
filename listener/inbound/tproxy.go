package inbound

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/log"
)

type TProxyOption struct {
	BaseOption
	UDP bool `inbound:"udp,omitempty"`
}

func (o TProxyOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type TProxy struct {
	*Base
	config *TProxyOption
	lUDP   []*tproxy.UDPListener
	lTCP   []*tproxy.Listener
	udp    bool
}

func NewTProxy(options *TProxyOption) (*TProxy, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &TProxy{
		Base:   base,
		config: options,
		udp:    options.UDP,
	}, nil

}

// Config implements constant.InboundListener
func (t *TProxy) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *TProxy) Address() string {
	var addrList []string
	for _, l := range t.lTCP {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *TProxy) Listen(tunnel C.Tunnel) (err error) {
	if len(t.lTCP) != 0 || len(t.lUDP) != 0 {
		return errors.New("listener is already running")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.Close())
		}
	}()
	for _, addr := range strings.Split(t.RawAddress(), ",") {
		lTCP, err := tproxy.New(addr, tunnel, t.Additions()...)
		if err != nil {
			return err
		}
		t.lTCP = append(t.lTCP, lTCP)
		if t.udp {
			lUDP, err := tproxy.NewUDP(addr, tunnel, t.Additions()...)
			if err != nil {
				return err
			}
			t.lUDP = append(t.lUDP, lUDP)
		}
	}
	log.Infoln("TProxy[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *TProxy) Close() error {
	var err error
	var errs []error
	t.lTCP, err = closeListeners(t.lTCP)
	if err != nil {
		errs = append(errs, err)
	}
	t.lUDP, err = closeListeners(t.lUDP)
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

var _ C.InboundListener = (*TProxy)(nil)
