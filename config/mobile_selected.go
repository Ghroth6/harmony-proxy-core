package config

import (
	"context"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/protection"
	"net"
	"net/netip"
	"sync/atomic"
)

type mobileCandidateDialer struct {
	generation atomic.Uint64
	attempts   atomic.Int32
	options    []dialer.Option
}

type mobilePhysicalDialer struct {
	fence   *mobileCandidateDialer
	options []dialer.Option
}

func (d *mobileCandidateDialer) newPhysical(options []dialer.Option) C.Dialer {
	return &mobilePhysicalDialer{fence: d, options: append([]dialer.Option(nil), options...)}
}
func (d *mobilePhysicalDialer) current(ctx context.Context) (context.Context, C.Dialer, error) {
	ctx, err := d.fence.context(ctx)
	if err != nil {
		return nil, nil, err
	}
	options := append(append([]dialer.Option(nil), d.fence.options...), d.options...)
	return ctx, dialer.NewDialer(options...), nil
}
func (d *mobilePhysicalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, physical, err := d.current(ctx)
	if err != nil {
		return nil, err
	}
	return physical.DialContext(ctx, network, address)
}
func (d *mobilePhysicalDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	ctx, physical, err := d.current(ctx)
	if err != nil {
		return nil, err
	}
	return physical.ListenPacket(ctx, network, address, remote)
}

func (d *mobileCandidateDialer) context(ctx context.Context) (context.Context, error) {
	if generation := d.generation.Load(); generation != 0 {
		return protection.WithGeneration(ctx, generation), nil
	}
	d.attempts.Add(1)
	return nil, errPreparationNetwork
}

// ActivateMobileNetwork is the explicit runtime-only transition after a real
// protection gate and matching online snapshot have been accepted. Preparation
// and saved candidates never invoke it. Retirement disables it again.
func (c *Config) ActivateMobileNetwork(generation uint64) error {
	if c == nil || generation == 0 || c.CheckCandidate() != nil {
		return &MobileValidationError{Code: "CANDIDATE_INVALID"}
	}
	if c.mobileNetwork != nil {
		c.mobileNetwork.generation.Store(generation)
	}
	return nil
}
