package inbound

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/anytls"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	httpListener "github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/snell"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/listener/sudoku"
	"github.com/metacubex/mihomo/listener/trojan"
	"github.com/metacubex/mihomo/listener/trusttunnel"
)

type readingConn struct {
	net.Conn
	started, returned chan struct{}
	once              sync.Once
}

func (c *readingConn) Read(b []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true; close(c.started) })
	if first {
		defer close(c.returned)
	}
	return c.Conn.Read(b)
}

type readingListener struct {
	net.Listener
	started, returned chan struct{}
}

func (l *readingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &readingConn{Conn: c, started: l.started, returned: l.returned}, nil
}

type readingListenConfig struct {
	C.InboundListenConfig
	listener *readingListener
}

func (c *readingListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := c.InboundListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c.listener = &readingListener{l, make(chan struct{}), make(chan struct{})}
	return c.listener, nil
}

func TestListenerLifecycleStopsAcceptedHandshakeSockets(t *testing.T) {
	// Enable is process-wide. Use a child test process so ordinary upstream
	// interop tests still exercise their original, non-embedded behavior.
	const child = "MIHOMO_TEST_INBOUND_FORWARDING_CHILD"
	if os.Getenv(child) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestListenerLifecycleStopsAcceptedHandshakeSockets$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("embedded listener test: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	factories := map[string]func(C.InboundListenConfig) (io.Closer, error){
		"anytls": func(lc C.InboundListenConfig) (io.Closer, error) {
			return anytls.New(LC.AnyTLSServer{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key}, lc, nil)
		},
		"vmess": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vmess.New(LC.VmessServer{Listen: "127.0.0.1:0"}, lc, nil)
		},
		"vless": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vless.New(LC.VlessServer{Listen: "127.0.0.1:0", AllowInsecure: true}, lc, nil)
		},
		"trojan": func(lc C.InboundListenConfig) (io.Closer, error) {
			return trojan.New(LC.TrojanServer{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key}, lc, nil)
		},
		"shadowsocks": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_shadowsocks.New(LC.ShadowsocksServer{Listen: "127.0.0.1:0", Cipher: "none"}, lc, nil)
		},
		"snell": func(lc C.InboundListenConfig) (io.Closer, error) {
			return snell.New(LC.SnellServer{Listen: "127.0.0.1:0", Psk: "test"}, lc, nil)
		},
		"sudoku": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sudoku.New(LC.SudokuServer{Listen: "127.0.0.1:0", Key: "test", DisableHTTPMask: true}, lc, nil)
		},
		"trusttunnel": func(lc C.InboundListenConfig) (io.Closer, error) {
			return trusttunnel.New(LC.TrustTunnelServer{Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key}, lc, nil)
		},
		"http": func(lc C.InboundListenConfig) (io.Closer, error) {
			return httpListener.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", AuthStore: authStore.Nil}, lc, nil, A.WithInName("owned-test"))
		},
		"socks": func(lc C.InboundListenConfig) (io.Closer, error) {
			return socks.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", AuthStore: authStore.Nil}, lc, nil, A.WithInName("owned-test"))
		},
		"mixed": func(lc C.InboundListenConfig) (io.Closer, error) {
			return mixed.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", AuthStore: authStore.Nil}, lc, nil, A.WithInName("owned-test"))
		},
	}
	forwarding.Enable()
	var generation uint64
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			generation++
			if err := forwarding.Start(context.Background(), generation); err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = forwarding.Stop(ctx)
			}()
			lc := &readingListenConfig{InboundListenConfig: A.NewListenConfig()}
			l, err := factory(lc)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			client, err := net.Dial("tcp", lc.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			select {
			case <-lc.listener.started:
			case <-time.After(time.Second):
				t.Fatal("protocol never read accepted socket")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := forwarding.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-lc.listener.returned:
			case <-ctx.Done():
				t.Fatal("accepted socket read remained blocked")
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err := client.Read(b[:]); err == nil {
				t.Fatal("peer remained open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("peer timed out instead of closing")
			}
		})
	}
}
