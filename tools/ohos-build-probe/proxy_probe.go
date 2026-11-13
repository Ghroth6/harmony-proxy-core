package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/tunnel"
)

var proxyProbe struct {
	sync.Mutex
	listener *mixed.Listener
	server   *http.Server
	done     chan struct{}
	requests atomic.Int64
}

// Decision probe: use upstream HTTP/SOCKS parsing and DIRECT forwarding.
// No executor.ApplyConfig, TUN, remote providers, periodic probes or heartbeat.
// The synthetic target and proxy bind only device loopback.
//
//export cb_probe_proxy_start
func cb_probe_proxy_start() *C.char {
	proxyProbe.Lock()
	defer proxyProbe.Unlock()
	if proxyProbe.listener != nil {
		return C.CString("already started")
	}
	cfg, err := config.Parse([]byte("mode: direct\nlog-level: silent\ndns:\n  enable: false\nprofile:\n  store-selected: false\nrules:\n  - MATCH,DIRECT\n"))
	if err != nil {
		return C.CString("parse failed: " + err.Error())
	}
	target, err := net.Listen("tcp4", "127.0.0.1:18687")
	if err != nil {
		return C.CString("target bind failed: " + err.Error())
	}
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	tunnel.SetMode(tunnel.Direct)
	// Same admission initialization as executor.updateListeners. Without it,
	// the default listener rejects every peer before HTTP/SOCKS negotiation.
	inbound.SetAllowedIPs(cfg.General.LanAllowedIPs)
	inbound.SetDisAllowedIPs(cfg.General.LanDisAllowedIPs)
	tunnel.OnRunning()
	listener, err := mixed.New("127.0.0.1:18686", tunnel.Tunnel)
	if err != nil {
		target.Close()
		tunnel.OnSuspend()
		return C.CString("proxy bind failed: " + err.Error())
	}
	proxyProbe.requests.Store(0)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Connection", "close")
			json.NewEncoder(w).Encode(map[string]any{"pid": os.Getpid(), "nonce": r.URL.Query().Get("nonce"),
				"request": proxyProbe.requests.Add(1), "at": time.Now().UTC(), "peer": r.RemoteAddr})
		})}
	server.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	proxyProbe.listener, proxyProbe.server, proxyProbe.done = listener, server, done
	go func() { defer close(done); server.Serve(target) }()
	return C.CString(fmt.Sprintf("started pid=%d mixed=%s target=%s TUN=false", os.Getpid(), listener.Address(), target.Addr()))
}

// Stop is called synchronously from extension onDestroy after start completes.
// If destroy races start, the start completion callback owns cleanup.
// It reports listener/server closure; process exit is observed separately.
//
//export cb_probe_proxy_stop
func cb_probe_proxy_stop() *C.char {
	proxyProbe.Lock()
	defer proxyProbe.Unlock()
	if proxyProbe.listener == nil {
		return C.CString("already stopped")
	}
	a := proxyProbe.listener.Close()
	b := proxyProbe.server.Close()
	<-proxyProbe.done
	tunnel.OnSuspend()
	proxyProbe.listener, proxyProbe.server, proxyProbe.done = nil, nil, nil
	return C.CString(fmt.Sprintf("stopped pid=%d proxyClose=%v targetClose=%v requests=%d serverJoined=true", os.Getpid(), a, b, proxyProbe.requests.Load()))
}
