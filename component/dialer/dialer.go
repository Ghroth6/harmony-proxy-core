package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/mptcp"
	"github.com/metacubex/mihomo/component/resolver"
)

const (
	DefaultTCPTimeout = 5 * time.Second
	DefaultUDPTimeout = DefaultTCPTimeout

	dualStackFallbackTimeout = 300 * time.Millisecond
)

var (
	tcpConcurrent = atomic.NewBool(false)
)

func SetTcpConcurrent(concurrent bool) {
	tcpConcurrent.Store(concurrent)
}

func GetTcpConcurrent() bool {
	return tcpConcurrent.Load()
}

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	ctx, finish, _, err := acquireNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	opt := applyOptions(options...)

	if opt.network == 4 || opt.network == 6 {
		if strings.Contains(network, "tcp") {
			network = "tcp"
		} else {
			network = "udp"
		}

		network = fmt.Sprintf("%s%d", network, opt.network)
	}

	ips, port, err := parseAddr(ctx, network, address, opt.resolver)
	if err != nil {
		return nil, err
	}

	tcpConcurrent := GetTcpConcurrent()

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		if tcpConcurrent {
			return parallelDialContext(ctx, network, ips, port, opt)
		}
		return serialDialContext(ctx, network, ips, port, opt)
	case "tcp", "udp":
		if tcpConcurrent {
			if opt.prefer != 4 && opt.prefer != 6 {
				return parallelDialContext(ctx, network, ips, port, opt)
			}
			return dualStackDialContext(ctx, parallelDialContext, network, ips, port, opt)
		}
		return dualStackDialContext(ctx, serialDialContext, network, ips, port, opt)
	default:
		return nil, ErrorInvalidedNetworkStack
	}
}

func ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort, options ...Option) (net.PacketConn, error) {
	ctx, finish, lifecycle, err := acquireNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	opt := applyOptions(options...)

	lc, address, err := listenConfig(ctx, network, address, rAddrPort, opt)
	if err != nil {
		return nil, err
	}
	conn, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if lifecycle != nil {
		return lifecycle.OwnPacketConn(ctx, conn)
	}
	return conn, nil
}

// Listen creates a TCP listener with the same socket policy as ListenPacket.
func Listen(ctx context.Context, network, address string, options ...Option) (net.Listener, error) {
	lc, address, err := listenConfig(ctx, network, address, netip.AddrPort{}, applyOptions(options...))
	if err != nil {
		return nil, err
	}
	return lc.Listen(ctx, network, address)
}

func listenConfig(ctx context.Context, network, address string, rAddrPort netip.AddrPort, opt option) (*net.ListenConfig, string, error) {
	lc := &net.ListenConfig{}
	if opt.addrReuse {
		addrReuseToListenConfig(lc)
	}
	if DefaultSocketHook != nil { // ignore interfaceName, routingMark when DefaultSocketHook not null (in CMFA)
		socketHookToListenConfig(lc)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(rAddrPort.Addr().Unmap())
			}
		}
		if rAddrPort.Addr().Unmap().IsLoopback() || listenAddressIsLoopback(address) {
			// avoid "The requested address is not valid in its context."
			opt.interfaceName = ""
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToListenConfig
			if opt.fallbackBind {
				bind = fallbackBindIfaceToListenConfig
			}
			addr, err := bind(opt.interfaceName, lc, network, address, rAddrPort)
			if err != nil {
				return nil, "", err
			}
			address = addr
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToListenConfig(opt.routingMark, lc, network, address)
		}
	}

	if policy := outboundSocketPolicy.Load(); policy != nil && policy.Required(ctx) {
		// ListenConfig has no ControlContext. Retain the original immutable
		// marked context explicitly; the generic listener helper uses Background.
		addControlToListenConfig(lc, func(_ context.Context, network, address string, raw syscall.RawConn) error {
			return policy.Control(ctx, network, address, raw)
		})
	}
	return lc, address, nil
}

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, opt option) (conn net.Conn, err error) {
	ctx, finish, lifecycle, err := acquireNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	defer func() {
		if lifecycle != nil && err == nil && conn != nil {
			conn, err = lifecycle.OwnConn(ctx, conn)
		}
	}()
	var address string
	destination, port = resolver.LookupIP4P(destination, port)
	address = net.JoinHostPort(destination.String(), port)

	netDialer := opt.netDialer
	policy := outboundSocketPolicy.Load()
	protected := policy != nil && policy.Required(ctx)
	switch netDialer.(type) {
	case nil:
		netDialer = &net.Dialer{}
	case *net.Dialer:
		_netDialer := *netDialer.(*net.Dialer)
		netDialer = &_netDialer // make a copy
	default:
		if protected {
			return nil, ErrUnsupportedSocketPolicyDialer
		}
		return netDialer.DialContext(ctx, network, address)
	}

	dialer := netDialer.(*net.Dialer)
	keepalive.SetNetDialer(dialer)
	mptcp.SetNetDialer(dialer, opt.mpTcp)
	if protected {
		addControlToDialer(dialer, policy.Control)
	}

	if DefaultSocketHook != nil { // ignore interfaceName, routingMark and tfo when DefaultSocketHook not null (in CMFA)
		socketHookToToDialer(dialer)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToDialer
			if opt.fallbackBind {
				bind = fallbackBindIfaceToDialer
			}
			if err := bind(opt.interfaceName, dialer, network, destination); err != nil {
				return nil, err
			}
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToDialer(opt.routingMark, dialer, network, destination)
		}
		if opt.tfo && !DisableTFO {
			return dialTFO(ctx, *dialer, network, address)
		}
	}

	conn, err = dialer.DialContext(ctx, network, address)
	return conn, err
}

func ICMPControl(destination netip.Addr) func(network, address string, conn syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		if DefaultSocketHook != nil {
			return DefaultSocketHook(network, address, conn)
		}
		dialer := &net.Dialer{}
		interfaceName := DefaultInterface.Load()
		if interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if interfaceName != "" {
			if err := bindIfaceToDialer(interfaceName, dialer, network, destination); err != nil {
				return err
			}
		}
		routingMark := int(DefaultRoutingMark.Load())
		if routingMark != 0 {
			bindMarkToDialer(routingMark, dialer, network, destination)
		}
		if dialer.ControlContext != nil {
			return dialer.ControlContext(context.TODO(), network, address, conn)
		}
		return nil
	}
}

type dialFunc func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error)

func dualStackDialContext(ctx context.Context, dialFn dialFunc, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	ipv4s, ipv6s := resolver.SortationAddr(ips)
	if len(ipv4s) == 0 && len(ipv6s) == 0 {
		return nil, ErrorNoIpAddress
	}
	if len(ipv4s) == 0 && len(ipv6s) != 0 {
		return dialFn(ctx, network, ipv6s, port, opt)
	}
	if len(ipv4s) != 0 && len(ipv6s) == 0 {
		return dialFn(ctx, network, ipv4s, port, opt)
	}

	preferIPVersion := opt.prefer
	fallbackTicker := time.NewTicker(dualStackFallbackTimeout)
	defer fallbackTicker.Stop()

	results := make(chan dialResult)
	returned := make(chan struct{})
	var returnedOnce sync.Once
	stopResults := func() { returnedOnce.Do(func() { close(returned) }) }
	defer stopResults()

	var wg sync.WaitGroup

	racer := func(ctx context.Context, finish func(), ips []netip.Addr, isPrimary bool) {
		defer wg.Done()
		defer finish()
		result := dialResult{isPrimary: isPrimary}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					closeWorkerConn(ctx, result.Conn)
				}
			}
		}()
		result.Conn, result.error = dialFn(ctx, network, ips, port, opt)
	}

	var admissionErrors []error
	launch := func(ips []netip.Addr, primary bool) {
		workerCtx, finish, err := acquireWorker(ctx)
		if err != nil {
			admissionErrors = append(admissionErrors, err)
			return
		}
		wg.Add(1)
		go racer(workerCtx, finish, ips, primary)
	}
	launch(ipv4s, preferIPVersion != 6)
	launch(ipv6s, preferIPVersion != 4)

	_, finishDrain, admissionErr := acquireWorker(ctx)
	if admissionErr != nil {
		stopResults()
		wg.Wait() // the admitted parent joins every actual child before return.
		return nil, admissionErr
	}
	go func() {
		defer finishDrain()
		wg.Wait()
		close(results)
	}()

	var fallback dialResult
	errs := admissionErrors

loop:
	for {
		select {
		case <-fallbackTicker.C:
			if fallback.error == nil && fallback.Conn != nil {
				return fallback.Conn, nil
			}
		case res, ok := <-results:
			if !ok {
				break loop
			}
			if res.error == nil {
				if res.isPrimary {
					if fallback.error == nil && fallback.Conn != nil {
						_, finish, admissionErr := acquireWorker(ctx)
						if admissionErr != nil {
							// Cancellation denies a new asynchronous owner. This
							// admitted parent must finish the real close itself.
							closeWorkerConn(ctx, fallback.Conn)
						} else {
							conn := fallback.Conn
							go func() { defer finish(); closeWorkerConn(ctx, conn) }()
						}
					}
					return res.Conn, nil
				}
				fallback = res
			} else {
				if res.isPrimary {
					errs = append([]error{fmt.Errorf("connect failed: %w", res.error)}, errs...)
				} else {
					errs = append(errs, fmt.Errorf("connect failed: %w", res.error))
				}
			}
		}
	}

	if fallback.error == nil && fallback.Conn != nil {
		return fallback.Conn, nil
	}
	return nil, errors.Join(errs...)
}

func parallelDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, ErrorNoIpAddress
	}
	if len(ips) == 1 {
		return dialContext(ctx, network, ips[0], port, opt)
	}
	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)
	racer := func(ctx context.Context, finish func(), ip netip.Addr) {
		defer finish()
		result := dialResult{isPrimary: true, ip: ip}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					closeWorkerConn(ctx, result.Conn)
				}
			}
		}()
		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	var errs []error
	admitted := 0
	for _, ip := range ips {
		workerCtx, finish, err := acquireWorker(ctx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		admitted++
		go racer(workerCtx, finish, ip)
	}
	for i := 0; i < admitted; i++ {
		res := <-results
		if res.error == nil {
			return res.Conn, nil
		}
		errs = append(errs, res.error)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, os.ErrDeadlineExceeded
}

func serialDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, ErrorNoIpAddress
	}
	var errs []error
	for _, ip := range ips {
		if conn, err := dialContext(ctx, network, ip, port, opt); err == nil {
			return conn, nil
		} else {
			errs = append(errs, err)
		}
	}
	return nil, errors.Join(errs...)
}

type dialResult struct {
	ip netip.Addr
	net.Conn
	error
	isPrimary bool
}

func parseAddr(ctx context.Context, network, address string, preferResolver resolver.Resolver) ([]netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "-1", err
	}

	if preferResolver == nil {
		preferResolver = resolver.ProxyServerHostResolver
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		ips, err = resolver.LookupIPv4WithResolver(ctx, host, preferResolver)
	case "tcp6", "udp6":
		ips, err = resolver.LookupIPv6WithResolver(ctx, host, preferResolver)
	default:
		ips, err = resolver.LookupIPWithResolver(ctx, host, preferResolver)
	}
	if err != nil {
		return nil, "-1", fmt.Errorf("dns resolve failed: %w", err)
	}
	for i, ip := range ips {
		if ip.Is4In6() {
			ips[i] = ip.Unmap()
		}
	}
	return ips, port, nil
}

func listenAddressIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

type Dialer struct {
	Opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.Opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, rAddrPort, WithOption(d.Opt))
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{Opt: opt}
}

// ResolveUDPAddresses reuses the normal proxy bootstrap resolver and explicit
// address-family options without substituting an opaque net.Dialer. Internal
// QUIC callers then create each physical socket through their PacketDialer.
func ResolveUDPAddresses(ctx context.Context, address string, options ...Option) ([]netip.AddrPort, error) {
	ctx, finish, _, err := acquireNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	opt := applyOptions(options...)
	if policy := outboundSocketPolicy.Load(); policy != nil && policy.Required(ctx) && opt.netDialer != nil {
		if _, ok := opt.netDialer.(*net.Dialer); !ok {
			return nil, ErrUnsupportedSocketPolicyDialer
		}
	}
	network := "udp"
	if opt.network == 4 {
		network = "udp4"
	}
	if opt.network == 6 {
		network = "udp6"
	}
	ips, portText, err := parseAddr(ctx, network, address, opt.resolver)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrorInvalidedNetworkStack
	}
	if len(ips) == 0 {
		return nil, ErrorNoIpAddress
	}
	if opt.prefer == 4 || opt.prefer == 6 {
		v4, v6 := resolver.SortationAddr(ips)
		if opt.prefer == 4 {
			ips = append(v4, v6...)
		} else {
			ips = append(v6, v4...)
		}
	}
	result := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		result = append(result, netip.AddrPortFrom(ip, uint16(port)))
	}
	return result, nil
}
