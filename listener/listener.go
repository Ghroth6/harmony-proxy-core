package listener

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/redir"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/listener/tuic"
	LT "github.com/metacubex/mihomo/listener/tunnel"
	"github.com/metacubex/mihomo/log"
)

var (
	allowLan    = false
	bindAddress = "*"

	socksListener       *socks.Listener
	socksUDPListener    *socks.UDPListener
	httpListener        *http.Listener
	redirListener       *redir.Listener
	redirUDPListener    *tproxy.UDPListener
	tproxyListener      *tproxy.Listener
	tproxyUDPListener   *tproxy.UDPListener
	mixedListener       *mixed.Listener
	mixedUDPLister      *socks.UDPListener
	tunnelTCPListeners  = map[string]*LT.Listener{}
	tunnelUDPListeners  = map[string]*LT.PacketConn{}
	inboundListeners    = map[string]C.InboundListener{}
	inboundPendingClose = map[string]C.InboundListener{}
	tunLister           *sing_tun.Listener
	shadowSocksListener C.MultiAddrListener
	vmessListener       *sing_vmess.Listener
	tuicListener        *tuic.Listener

	// lock for recreate function
	socksMux   sync.Mutex
	httpMux    sync.Mutex
	redirMux   sync.Mutex
	tproxyMux  sync.Mutex
	mixedMux   sync.Mutex
	tunnelMux  sync.Mutex
	inboundMux sync.Mutex
	tunMux     sync.Mutex
	ssMux      sync.Mutex
	vmessMux   sync.Mutex
	tuicMux    sync.Mutex

	LastTunConf  LC.Tun
	LastTuicConf LC.TuicServer
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	TProxyPort        int    `json:"tproxy-port"`
	MixedPort         int    `json:"mixed-port"`
	ShadowSocksConfig string `json:"ss-config"`
	VmessConfig       string `json:"vmess-config"`
}

func GetTunConf() LC.Tun {
	if tunLister == nil {
		return LastTunConf
	}
	return tunLister.Config()
}

func GetTuicConf() LC.TuicServer {
	if tuicListener == nil {
		return LC.TuicServer{Enable: false}
	}
	return tuicListener.Config()
}

func AllowLan() bool {
	return allowLan
}

func BindAddress() string {
	return bindAddress
}

func SetAllowLan(al bool) {
	allowLan = al
}

func SetBindAddress(host string) {
	bindAddress = host
}

// ReCreateHTTP replaces the HTTP entrypoint and reports its actual bind/close result.
func ReCreateHTTP(port int, tunnel C.Tunnel) (err error) {
	httpMux.Lock()
	defer httpMux.Unlock()
	defer logListenerError("HTTP", &err)
	addr := genAddr(bindAddress, port, allowLan)
	if httpListener != nil && httpListener.RawAddress() == addr {
		return nil
	}
	if err = closeAndClear(&httpListener); err != nil {
		return err
	}
	if portIsZero(addr) {
		return nil
	}
	next, err := http.New(addr, tunnel)
	if err != nil {
		return err
	}
	httpListener = next
	log.Infoln("HTTP proxy listening at: %s", httpListener.Address())
	return nil
}

func ReCreateSocks(port int, tunnel C.Tunnel) (err error) {
	socksMux.Lock()
	defer socksMux.Unlock()
	defer logListenerError("SOCKS", &err)
	addr := genAddr(bindAddress, port, allowLan)
	err = recreatePair(&socksListener, &socksUDPListener, addr,
		func() (*socks.Listener, error) { return socks.New(addr, tunnel) },
		func() (*socks.UDPListener, error) { return socks.NewUDP(addr, tunnel) })
	if err == nil && socksListener != nil {
		log.Infoln("SOCKS proxy listening at: %s", socksListener.Address())
	}
	return err
}

func ReCreateRedir(port int, tunnel C.Tunnel) (err error) {
	redirMux.Lock()
	defer redirMux.Unlock()
	defer logListenerError("Redir", &err)
	addr := genAddr(bindAddress, port, allowLan)
	err = recreatePair(&redirListener, &redirUDPListener, addr,
		func() (*redir.Listener, error) { return redir.New(addr, tunnel) },
		func() (*tproxy.UDPListener, error) { return tproxy.NewUDP(addr, tunnel) })
	if err == nil && redirListener != nil {
		log.Infoln("Redirect proxy listening at: %s", redirListener.Address())
	}
	return err
}

func ReCreateShadowSocks(shadowSocksConfig string, tunnel C.Tunnel) (err error) {
	ssMux.Lock()
	defer ssMux.Unlock()
	defer logListenerError("ShadowSocks", &err)
	var config LC.ShadowsocksServer
	if shadowSocksConfig != "" {
		addr, cipher, password, parseErr := embedSS.ParseSSURL(shadowSocksConfig)
		if parseErr != nil {
			return parseErr
		}
		if addr == "" {
			return errors.New("missing ShadowSocks listen address")
		}
		config = LC.ShadowsocksServer{Enable: true, Listen: addr, Cipher: cipher, Password: password, Udp: true}
	}
	if shadowSocksListener != nil && shadowSocksListener.Config() == config.String() {
		return nil
	}
	if err = closeAndClear(&shadowSocksListener); err != nil || !config.Enable {
		return err
	}
	next, err := sing_shadowsocks.New(config, inbound.NewListenConfig(), tunnel)
	if err != nil {
		return err
	}
	shadowSocksListener = next
	for _, addr := range shadowSocksListener.AddrList() {
		log.Infoln("ShadowSocks proxy listening at: %s", addr.String())
	}
	return nil
}

func ReCreateVmess(vmessConfig string, tunnel C.Tunnel) (err error) {
	vmessMux.Lock()
	defer vmessMux.Unlock()
	defer logListenerError("Vmess", &err)
	var config LC.VmessServer
	if vmessConfig != "" {
		addr, username, password, parseErr := sing_vmess.ParseVmessURL(vmessConfig)
		if parseErr != nil {
			return parseErr
		}
		if addr == "" {
			return errors.New("missing Vmess listen address")
		}
		config = LC.VmessServer{Enable: true, Listen: addr, Users: []LC.VmessUser{{Username: username, UUID: password, AlterID: 1}}}
	}
	if vmessListener != nil && vmessListener.Config() == config.String() {
		return nil
	}
	if err = closeAndClear(&vmessListener); err != nil || !config.Enable {
		return err
	}
	next, err := sing_vmess.New(config, inbound.NewListenConfig(), tunnel)
	if err != nil {
		return err
	}
	vmessListener = next
	for _, addr := range vmessListener.AddrList() {
		log.Infoln("Vmess proxy listening at: %s", addr.String())
	}
	return nil
}

func ReCreateTuic(config LC.TuicServer, tunnel C.Tunnel) (err error) {
	tuicMux.Lock()
	defer tuicMux.Unlock()
	defer logListenerError("Tuic", &err)
	if tuicListener != nil && LastTuicConf.String() == config.String() {
		return nil
	}
	LastTuicConf = LC.TuicServer{Enable: false}
	if err = closeAndClear(&tuicListener); err != nil {
		return err
	}
	if !config.Enable {
		return nil
	}
	next, err := tuic.New(config, inbound.NewListenConfig(), tunnel)
	if err != nil {
		return err
	}
	tuicListener = next
	LastTuicConf = config
	for _, addr := range tuicListener.AddrList() {
		log.Infoln("Tuic proxy listening at: %s", addr.String())
	}
	return nil
}

func ReCreateTProxy(port int, tunnel C.Tunnel) (err error) {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()
	defer logListenerError("TProxy", &err)
	addr := genAddr(bindAddress, port, allowLan)
	err = recreatePair(&tproxyListener, &tproxyUDPListener, addr,
		func() (*tproxy.Listener, error) { return tproxy.New(addr, tunnel) },
		func() (*tproxy.UDPListener, error) { return tproxy.NewUDP(addr, tunnel) })
	if err == nil && tproxyListener != nil {
		log.Infoln("TProxy server listening at: %s", tproxyListener.Address())
	}
	return err
}

func ReCreateMixed(port int, tunnel C.Tunnel) (err error) {
	mixedMux.Lock()
	defer mixedMux.Unlock()
	defer logListenerError("Mixed(http+socks)", &err)
	addr := genAddr(bindAddress, port, allowLan)
	err = recreatePair(&mixedListener, &mixedUDPLister, addr,
		func() (*mixed.Listener, error) { return mixed.New(addr, tunnel) },
		func() (*socks.UDPListener, error) { return socks.NewUDP(addr, tunnel) })
	if err == nil && mixedListener != nil {
		log.Infoln("Mixed(http+socks) proxy listening at: %s", mixedListener.Address())
	}
	return err
}

func ReCreateTun(tunConf LC.Tun, tunnel C.Tunnel) {
	tunConf.Sort()

	tunMux.Lock()
	defer func() {
		LastTunConf = tunConf
		tunMux.Unlock()
	}()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TUN listening error: %s", err.Error())
			tunConf.Enable = false
		}
	}()

	if tunConf.Equal(LastTunConf) {
		if tunLister != nil { // some default value in dialer maybe changed when config reload, reset at here
			tunLister.OnReload()
		}
		return
	}

	closeTunListener()

	if !tunConf.Enable {
		return
	}

	lister, err := sing_tun.New(tunConf, tunnel)
	if err != nil {
		return
	}
	tunLister = lister

	log.Infoln("[TUN] Tun adapter listening at: %s", tunLister.Address())
}

type tunnelCloseKey struct{ network, key string }

// PatchTunnel applies the requested set. On failure, sockets created by this
// call are closed; unchanged sockets remain. Removed/replaced sockets are not
// restored. An error is never a readiness result for the requested set.
func PatchTunnel(tunnels []LC.Tunnel, tunnel C.Tunnel) (err error) {
	tunnelMux.Lock()
	defer tunnelMux.Unlock()
	defer logListenerError("Tunnel", &err)
	var errs []error
	pendingListenerCloses.Range(func(key, value any) bool {
		if key, ok := key.(tunnelCloseKey); ok {
			if err := closeRetired(key, value.(io.Closer)); err != nil {
				errs = append(errs, fmt.Errorf("close %s tunnel %s: %w", key.network, key.key, err))
			}
		}
		return true
	})

	tcpWanted := make(map[string]LC.Tunnel)
	udpWanted := make(map[string]LC.Tunnel)
	for _, config := range tunnels {
		key := fmt.Sprintf("%s/%s/%s", config.Address, config.Target, config.Proxy)
		for _, network := range config.Network {
			switch network {
			case "tcp":
				tcpWanted[key] = config
			case "udp":
				udpWanted[key] = config
			default:
				return fmt.Errorf("invalid tunnel network %q", network)
			}
		}
	}
	for _, key := range sortedKeys(tunnelTCPListeners) {
		if _, keep := tcpWanted[key]; !keep {
			if err := closeRetired(tunnelCloseKey{"tcp", key}, tunnelTCPListeners[key]); err != nil {
				errs = append(errs, fmt.Errorf("close TCP tunnel %s: %w", key, err))
			}
			delete(tunnelTCPListeners, key)
		}
	}
	for _, key := range sortedKeys(tunnelUDPListeners) {
		if _, keep := udpWanted[key]; !keep {
			if err := closeRetired(tunnelCloseKey{"udp", key}, tunnelUDPListeners[key]); err != nil {
				errs = append(errs, fmt.Errorf("close UDP tunnel %s: %w", key, err))
			}
			delete(tunnelUDPListeners, key)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	tcpCreated := make(map[string]*LT.Listener)
	udpCreated := make(map[string]*LT.PacketConn)
	lc := inbound.NewListenConfig()
	for _, key := range sortedKeys(tcpWanted) {
		if _, exists := tunnelTCPListeners[key]; exists {
			continue
		}
		config := tcpWanted[key]
		l, err := LT.New(config.Address, config.Target, config.Proxy, lc, tunnel)
		if err != nil {
			errs = append(errs, fmt.Errorf("bind TCP tunnel %s: %w", key, err))
			break
		}
		tcpCreated[key] = l
	}
	if len(errs) == 0 {
		for _, key := range sortedKeys(udpWanted) {
			if _, exists := tunnelUDPListeners[key]; exists {
				continue
			}
			config := udpWanted[key]
			l, err := LT.NewUDP(config.Address, config.Target, config.Proxy, lc, tunnel)
			if err != nil {
				errs = append(errs, fmt.Errorf("bind UDP tunnel %s: %w", key, err))
				break
			}
			udpCreated[key] = l
		}
	}
	if len(errs) != 0 {
		for key, l := range tcpCreated {
			if err := closeRetired(tunnelCloseKey{"tcp", key}, l); err != nil {
				errs = append(errs, fmt.Errorf("rollback TCP tunnel %s: %w", key, err))
			}
		}
		for key, l := range udpCreated {
			if err := closeRetired(tunnelCloseKey{"udp", key}, l); err != nil {
				errs = append(errs, fmt.Errorf("rollback UDP tunnel %s: %w", key, err))
			}
		}
		return errors.Join(errs...)
	}
	for key, l := range tcpCreated {
		tunnelTCPListeners[key] = l
		log.Infoln("Tunnel(tcp/%s) listening at: %s", key, l.Address())
	}
	for key, l := range udpCreated {
		tunnelUDPListeners[key] = l
		log.Infoln("Tunnel(udp/%s) listening at: %s", key, l.Address())
	}
	return nil
}

// PatchInboundListeners reports real Listen/Close results. A failed batch rolls
// back its new listeners, preserving only unchanged existing listeners. Objects
// whose Close failed are kept separately for the next cleanup attempt, never as
// ready listeners. Callers must not treat an error as a usable configuration.
func PatchInboundListeners(newListenerMap map[string]C.InboundListener, tunnel C.Tunnel, dropOld bool) (err error) {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	defer logListenerError("Inbound", &err)
	var errs []error
	closeNamed := func(name string, l C.InboundListener) {
		if err := closeError(l); err != nil {
			errs = append(errs, fmt.Errorf("close listener %s: %w", name, err))
			inboundPendingClose[name] = l
		} else {
			delete(inboundPendingClose, name)
		}
	}
	for _, name := range sortedKeys(inboundPendingClose) {
		closeNamed(name, inboundPendingClose[name])
	}
	for _, name := range sortedKeys(inboundListeners) {
		old := inboundListeners[name]
		next, exists := newListenerMap[name]
		if (exists && (next == nil || !old.Config().Equal(next.Config()))) || (!exists && dropOld) {
			delete(inboundListeners, name)
			closeNamed(name, old)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	created := make(map[string]C.InboundListener)
	for _, name := range sortedKeys(newListenerMap) {
		if _, exists := inboundListeners[name]; exists {
			continue
		}
		next := newListenerMap[name]
		if next == nil {
			errs = append(errs, fmt.Errorf("listener %s is nil", name))
			break
		}
		if err := next.Listen(tunnel); err != nil {
			errs = append(errs, fmt.Errorf("listen %s: %w", name, err))
			closeNamed(name, next)
			break
		}
		created[name] = next
	}
	if len(errs) != 0 {
		for _, name := range sortedKeys(created) {
			closeNamed(name, created[name])
		}
		return errors.Join(errs...)
	}
	for name, l := range created {
		inboundListeners[name] = l
	}
	return nil
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	if tproxyListener != nil {
		_, portStr, _ := net.SplitHostPort(tproxyListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.TProxyPort = port
	}

	if mixedListener != nil {
		_, portStr, _ := net.SplitHostPort(mixedListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MixedPort = port
	}

	if shadowSocksListener != nil {
		ports.ShadowSocksConfig = shadowSocksListener.Config()
	}

	if vmessListener != nil {
		ports.VmessConfig = vmessListener.Config()
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(host string, port int, allowLan bool) string {
	if allowLan {
		if host == "*" {
			return fmt.Sprintf(":%d", port)
		}
		return fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}

func closeTunListener() {
	if tunLister != nil {
		tunLister.Close()
		tunLister = nil
	}
}

func Cleanup() {
	closeTunListener()
}
