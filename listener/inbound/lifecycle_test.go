package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/hysteria2_realm"
	"github.com/metacubex/mihomo/listener/shadowquic"
	"github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/snell"
	"github.com/metacubex/mihomo/listener/trojan"
	"github.com/metacubex/mihomo/listener/trusttunnel"
	"github.com/metacubex/mihomo/listener/tuic"
)

// Windows excludes different ranges for TCP and UDP; find a port valid for both.
func lifecycleReservePair(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
			return tcp, udp
		}
		_ = tcp.Close()
	}
	t.Fatal("could not reserve a TCP/UDP loopback pair")
	return nil, nil
}

func lifecycleAssertReleased(t *testing.T, address string) {
	t.Helper()
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TCP socket leaked at %s: %v", address, err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("UDP socket leaked at %s: %v", address, err)
	}
	_ = udp.Close()
}

type lifecycleListenConfig struct {
	C.InboundListenConfig
	bound []string
}

func (c *lifecycleListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := c.InboundListenConfig.Listen(ctx, network, address)
	if err == nil {
		c.bound = append(c.bound, address)
	}
	return l, err
}

func (c *lifecycleListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	l, err := c.InboundListenConfig.ListenPacket(ctx, network, address)
	if err == nil {
		c.bound = append(c.bound, address)
	}
	return l, err
}

func TestListenerLifecycleNamedRollbackAndRestart(t *testing.T) {
	factories := map[string]func(BaseOption) (C.InboundListener, error){
		"http":  func(b BaseOption) (C.InboundListener, error) { return NewHTTP(&HTTPOption{BaseOption: b}) },
		"socks": func(b BaseOption) (C.InboundListener, error) { return NewSocks(&SocksOption{BaseOption: b, UDP: true}) },
		"mixed": func(b BaseOption) (C.InboundListener, error) { return NewMixed(&MixedOption{BaseOption: b, UDP: true}) },
		"tunnel": func(b BaseOption) (C.InboundListener, error) {
			return NewTunnel(&TunnelOption{BaseOption: b, Network: []string{"tcp", "udp"}, Target: "127.0.0.1:9"})
		},
		"sudoku": func(b BaseOption) (C.InboundListener, error) {
			return NewSudoku(&SudokuOption{BaseOption: b, Key: "lifecycle-test-key", DisableHTTPMask: true})
		},
	}
	for name, factory := range factories {
		for _, conflict := range []string{"tcp", "udp"} {
			if conflict == "udp" && (name == "http" || name == "sudoku") {
				continue
			}
			t.Run(name+"/"+conflict, func(t *testing.T) {
				firstTCP, firstUDP := lifecycleReservePair(t)
				first := firstTCP.Addr().String()
				secondTCP, secondUDP := lifecycleReservePair(t)
				second := secondTCP.Addr().String()
				_ = firstTCP.Close()
				_ = firstUDP.Close()
				if conflict == "tcp" {
					_ = secondUDP.Close()
				} else {
					_ = secondTCP.Close()
				}
				_, firstPort, _ := net.SplitHostPort(first)
				_, secondPort, _ := net.SplitHostPort(second)
				lc := &lifecycleListenConfig{InboundListenConfig: A.NewListenConfig()}
				l, err := factory(BaseOption{NameStr: "rollback", Listen: "127.0.0.1", Port: firstPort + "/" + secondPort, ListenConfigForAPI: lc})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				if err := l.Listen(nil); err == nil {
					t.Fatal("expected actual bind conflict")
				}
				if len(lc.bound) == 0 || lc.bound[0] != first {
					t.Fatal("did not exercise a successful first bind")
				}
				if l.Address() != "" {
					t.Fatalf("failed Listen retained closed handles: %s", l.Address())
				}
				lifecycleAssertReleased(t, first)
				if err := l.Close(); err != nil {
					t.Fatalf("Close after rollback: %v", err)
				}
				_ = secondTCP.Close()
				_ = secondUDP.Close()
				for round := 0; round < 3; round++ {
					if err := l.Listen(nil); err != nil {
						t.Fatalf("restart: %v", err)
					}
					before := l.Address()
					if err := l.Listen(nil); err == nil {
						t.Fatal("duplicate Listen replaced live handles")
					}
					if l.Address() != before {
						t.Fatal("duplicate Listen changed owned handles")
					}
					if strings.Count(before, first) != 1 && name != "tunnel" {
						t.Fatalf("stale address accumulation: %s", before)
					}
					if err := l.Close(); err != nil {
						t.Fatal(err)
					}
					if err := l.Close(); err != nil {
						t.Fatalf("repeated Close: %v", err)
					}
					if l.Address() != "" {
						t.Fatalf("Close retained old addresses: %s", l.Address())
					}
					lifecycleAssertReleased(t, first)
					lifecycleAssertReleased(t, second)
				}
			})
		}
	}
}

func TestListenerLifecycleProtocolConstructorRollback(t *testing.T) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	type factory struct {
		network string
		new     func(string, C.InboundListenConfig) (io.Closer, error)
	}
	factories := map[string]factory{
		"sing-ss": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return sing_shadowsocks.New(LC.ShadowsocksServer{Listen: a, Cipher: "none", Udp: true}, lc, nil)
		}},
		"embedded-ss": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return shadowsocks.New(LC.ShadowsocksServer{Listen: a, Cipher: "aes-128-gcm", Password: "test", Udp: true}, lc, nil)
		}},
		"vmess": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vmess.New(LC.VmessServer{Listen: a, Users: []LC.VmessUser{{UUID: "00000000-0000-0000-0000-000000000001", AlterID: 64}}}, lc, nil)
		}},
		"vless": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vless.New(LC.VlessServer{Listen: a, AllowInsecure: true}, lc, nil)
		}},
		"anytls": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return anytls.New(LC.AnyTLSServer{Listen: a, AllowInsecure: true}, lc, nil)
		}},
		"trojan": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return trojan.New(LC.TrojanServer{Listen: a, AllowInsecure: true}, lc, nil)
		}},
		"snell": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return snell.New(LC.SnellServer{Listen: a, Psk: "test"}, lc, nil)
		}},
		"realm": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return hysteria2_realm.New(LC.Hysteria2RealmServer{Listen: a, Token: "test"}, lc, nil)
		}},
		"trusttunnel": {"tcp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return trusttunnel.New(LC.TrustTunnelServer{Listen: a, Certificate: cert, PrivateKey: key, Network: []string{"tcp", "udp"}}, lc, nil)
		}},
		"tuic": {"udp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return tuic.New(LC.TuicServer{Listen: a, Certificate: cert, PrivateKey: key, Token: []string{"test"}}, lc, nil)
		}},
		"hysteria2": {"udp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return sing_hysteria2.New(LC.Hysteria2Server{Listen: a, Certificate: cert, PrivateKey: key}, lc, nil)
		}},
		"shadowquic": {"udp", func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return shadowquic.New(LC.ShadowQuicServer{Listen: a, JLSUpstream: LC.ShadowQuicJLSUpstream{Addr: "127.0.0.1:9"}}, lc, nil)
		}},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			firstTCP, firstUDP := lifecycleReservePair(t)
			first := firstTCP.Addr().String()
			secondTCP, secondUDP := lifecycleReservePair(t)
			second := secondTCP.Addr().String()
			_ = firstTCP.Close()
			_ = firstUDP.Close()
			if factory.network == "tcp" {
				_ = secondUDP.Close()
			} else {
				_ = secondTCP.Close()
			}
			lc := &lifecycleListenConfig{InboundListenConfig: A.NewListenConfig()}
			l, err := factory.new(first+","+second, lc)
			if err == nil {
				_ = l.Close()
				t.Fatal("expected second address bind failure")
			}
			if len(lc.bound) == 0 || lc.bound[0] != first {
				t.Fatalf("failed before first socket bind: %v", err)
			}
			lifecycleAssertReleased(t, first)
			_ = secondTCP.Close()
			_ = secondUDP.Close()
			lifecycleAssertReleased(t, second)
			l, err = factory.new(first+","+second, A.NewListenConfig())
			if err != nil {
				t.Fatalf("fresh constructor after rollback: %v", err)
			}
			if err := l.Close(); err != nil {
				t.Fatalf("normal close: %v", err)
			}
			if err := l.Close(); err != nil {
				t.Fatalf("repeated close: %v", err)
			}
			lifecycleAssertReleased(t, first)
			lifecycleAssertReleased(t, second)
		})
	}
}

type lifecycleRetryCloser struct {
	calls int
	err   error
}

func (c *lifecycleRetryCloser) Close() error {
	c.calls++
	if c.calls == 1 {
		return c.err
	}
	return nil
}
func (*lifecycleRetryCloser) Address() string      { return "test" }
func (*lifecycleRetryCloser) Config() string       { return "" }
func (*lifecycleRetryCloser) AddrList() []net.Addr { return nil }

type lifecycleUnwrapNilError struct{}

func (lifecycleUnwrapNilError) Error() string { return "error with no wrapped cause" }
func (lifecycleUnwrapNilError) Unwrap() error { return nil }

func TestListenerLifecycleCloseRetainsFailedHandles(t *testing.T) {
	if err := closeListener(&lifecycleRetryCloser{err: lifecycleUnwrapNilError{}}); err == nil {
		t.Fatal("a nil unwrap cause must not hide a real error")
	}
	want := errors.New("transient close error")
	failed := &lifecycleRetryCloser{err: errors.Join(net.ErrClosed, want)}
	closed := &lifecycleRetryCloser{err: net.ErrClosed}
	remaining, err := closeListeners([]*lifecycleRetryCloser{failed, closed})
	if !errors.Is(err, want) || errors.Is(err, net.ErrClosed) || len(remaining) != 1 || remaining[0] != failed {
		t.Fatal("unknown close failure lost ownership")
	}
	remaining, err = closeListeners(remaining)
	if err != nil || len(remaining) != 0 || failed.calls != 2 {
		t.Fatal("failed handle could not be retried")
	}
	failed = &lifecycleRetryCloser{err: want}
	named := &ShadowSocks{l: failed}
	if !errors.Is(named.Close(), want) || named.l == nil {
		t.Fatal("single-handle wrapper lost failed ownership")
	}
	if err := named.Close(); err != nil || named.l != nil {
		t.Fatal("single-handle close retry failed")
	}
	if err := named.Close(); err != nil {
		t.Fatal("nil handle Close is not idempotent")
	}
}

func TestListenerLifecycleRejectedProtocolReleasesSocket(t *testing.T) {
	constructors := map[string]func(string, C.InboundListenConfig) (io.Closer, error){
		"anytls": func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return anytls.New(LC.AnyTLSServer{Listen: a}, lc, nil)
		},
		"trojan": func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return trojan.New(LC.TrojanServer{Listen: a}, lc, nil)
		},
		"vless": func(a string, lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vless.New(LC.VlessServer{Listen: a}, lc, nil)
		},
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			tcp, udp := lifecycleReservePair(t)
			address := tcp.Addr().String()
			_ = tcp.Close()
			_ = udp.Close()
			lc := &lifecycleListenConfig{InboundListenConfig: A.NewListenConfig()}
			l, err := construct(address, lc)
			if err == nil {
				_ = l.Close()
				t.Fatal("insecure config unexpectedly accepted")
			}
			if len(lc.bound) != 1 {
				t.Fatal("did not exercise post-bind validation")
			}
			lifecycleAssertReleased(t, address)
		})
	}
}

func TestListenerLifecycleInvalidLegacyCipherIsNilSafe(t *testing.T) {
	l, err := sing_shadowsocks.New(LC.ShadowsocksServer{Listen: "127.0.0.1:0", Cipher: "invalid-test-cipher"}, A.NewListenConfig(), nil)
	if err == nil || l != nil {
		t.Fatal("failed fallback must return a nil interface")
	}
	named, err := NewShadowSocks(&ShadowSocksOption{BaseOption: BaseOption{NameStr: "invalid", Listen: "127.0.0.1"}, Cipher: "invalid-test-cipher"})
	if err != nil {
		t.Fatal(err)
	}
	if err := named.Listen(nil); err == nil {
		t.Fatal("invalid cipher accepted")
	}
	if err := named.Close(); err != nil {
		t.Fatal(err)
	}
	if err := named.Close(); err != nil {
		t.Fatal(err)
	}
}
