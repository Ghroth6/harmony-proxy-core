package config

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/lifecycle"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/configresources"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

var errPreparationNetwork = errors.New("preparation network is forbidden")

type preparationDialer struct {
	attempts atomic.Int32
	observer func()
}

func (d *preparationDialer) denied() error {
	d.attempts.Add(1)
	if d.observer != nil {
		d.observer()
	}
	return errPreparationNetwork
}
func (d *preparationDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.denied()
}
func (d *preparationDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, d.denied()
}

var _ C.Dialer = (*preparationDialer)(nil)

type preparationProxyLookup struct {
	guard *preparationDialer
}

func (t *preparationProxyLookup) Proxies() map[string]C.Proxy {
	_ = t.guard.denied()
	return nil
}

// ValidateMobileNode constructs and fully discards a node through real engine
// adapters. All constructor network requests are denied at the C.Dialer system
// boundary. The optional observer reports attempts, never destinations or data.
func ValidateMobileNode(node map[string]any, networkObserver func()) (err error) {
	owned := &configresources.Set{}
	resources := &lifecycle.Group{}
	defer func() { err = errors.Join(err, resources.Close()) }()
	guard := &preparationDialer{observer: networkObserver}
	defer func() {
		if recover() != nil {
			err = &MobileValidationError{Code: "CORE_FAILURE"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := owned.Close(ctx); closeErr != nil {
			err = &MobileValidationError{Code: "CANDIDATE_CLEANUP_FAILED", cause: closeErr}
		}
		if guard.attempts.Load() != 0 {
			err = &MobileValidationError{Code: "PREPARATION_NETWORK_FORBIDDEN", cause: err}
		}
	}()
	proxy, parseErr := adapter.ParseProxy(node, adapter.WithPhysicalDialerForAPI(func([]dialer.Option) C.Dialer { return guard }), adapter.WithProxyLookupForAPI(&preparationProxyLookup{guard: guard}), adapter.WithResourcePolicyForAPI(mobileResourcePolicy), adapter.WithResourceOwner(resources))
	if proxy != nil {
		owned.AddProxy(proxy)
	}
	if parseErr != nil {
		if errors.Is(parseErr, adapter.ErrUnsupportedProxyType) {
			return &MobileValidationError{Code: "PROXY_TYPE_UNSUPPORTED", cause: parseErr}
		}
		var gap *outbound.APIIntegrationError
		if errors.As(parseErr, &gap) {
			return &MobileValidationError{Code: gap.Code, cause: parseErr}
		}
		return &MobileValidationError{Code: "PROXY_INVALID", cause: parseErr}
	}
	return nil
}

func mobileResourcePolicy(operation string) error {
	return &outbound.APIIntegrationError{Code: operation}
}

// MobileNodeFields retains the existing public validation entrypoint. Original
// fields, ciphers, endpoints and protocols are interpreted by the pinned engine,
// with construction and owned cleanup behind the preparation network fence.
func MobileNodeFields(node map[string]any) error {
	return ValidateMobileNode(node, nil)
}
