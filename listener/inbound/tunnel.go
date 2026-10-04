package inbound

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LT "github.com/metacubex/mihomo/listener/tunnel"
	"github.com/metacubex/mihomo/log"
)

type TunnelOption struct {
	BaseOption
	Network []string `inbound:"network"`
	Target  string   `inbound:"target"`
}

func (o TunnelOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Tunnel struct {
	*Base
	config *TunnelOption
	ttl    []*LT.Listener
	tul    []*LT.PacketConn
}

func NewTunnel(options *TunnelOption) (*Tunnel, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Tunnel{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (t *Tunnel) Config() C.InboundConfig {
	return t.config
}

// Close implements constant.InboundListener
func (t *Tunnel) Close() error {
	var err error
	var errs []error
	t.ttl, err = closeListeners(t.ttl)
	if err != nil {
		errs = append(errs, err)
	}
	t.tul, err = closeListeners(t.tul)
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Address implements constant.InboundListener
func (t *Tunnel) Address() string {
	var addrList []string
	for _, l := range t.ttl {
		addrList = append(addrList, "tcp://"+l.Address())
	}
	for _, l := range t.tul {
		addrList = append(addrList, "udp://"+l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *Tunnel) Listen(tunnel C.Tunnel) (err error) {
	if len(t.ttl) != 0 || len(t.tul) != 0 {
		return errors.New("listener is already running")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.Close())
		}
	}()
	lc := t.ListenConfig()
	for _, addr := range strings.Split(t.RawAddress(), ",") {
		for _, network := range t.config.Network {
			switch network {
			case "tcp":
				ttl, err := LT.New(addr, t.config.Target, t.config.SpecialProxy, lc, tunnel, t.Additions()...)
				if err != nil {
					return err
				}
				t.ttl = append(t.ttl, ttl)
			case "udp":
				tul, err := LT.NewUDP(addr, t.config.Target, t.config.SpecialProxy, lc, tunnel, t.Additions()...)
				if err != nil {
					return err
				}
				t.tul = append(t.tul, tul)
			default:
				log.Warnln("unknown network type: %s, passed", network)
				continue
			}
		}
	}
	log.Infoln("Tunnel[%s](%s)proxy listening at: %s", t.Name(), t.config.Target, t.Address())
	return nil
}

var _ C.InboundListener = (*Tunnel)(nil)
