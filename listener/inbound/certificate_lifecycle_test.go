package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	httpListener "github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/hysteria2_realm"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/listener/trojan"
	"github.com/metacubex/mihomo/listener/trusttunnel"
	"github.com/metacubex/mihomo/listener/tuic"
)

func certificateWorkers() int {
	b := make([]byte, 4<<20)
	n := runtime.Stack(b, true)
	count := 0
	for _, stack := range strings.Split(string(b[:n]), "\n\n") {
		if strings.Contains(stack, "github.com/metacubex/fswatch.") || strings.Contains(stack, "github.com/metacubex/mihomo/component/ca.(*ownedKeyPairWatcher).Start.func") {
			count++
		}
	}
	return count
}

type certificateFailListen struct{ C.InboundListenConfig }

var errCertificateBind = errors.New("injected bind failure after certificate loading")

func (certificateFailListen) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errCertificateBind
}
func (certificateFailListen) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errCertificateBind
}

func TestListenerLifecycleCertificateFiles(t *testing.T) {
	// Explicit Close must work even while the caller retains the Listener and
	// without depending on the timing of garbage collection or finalizers.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	root := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(root)
	defer C.SetHomeDir(old)
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cert": cert, "key": key} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	factories := map[string]func(C.InboundListenConfig) (io.Closer, error){
		"anytls": func(lc C.InboundListenConfig) (io.Closer, error) {
			return anytls.New(LC.AnyTLSServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"vmess": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vmess.New(LC.VmessServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"vless": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_vless.New(LC.VlessServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"trojan": func(lc C.InboundListenConfig) (io.Closer, error) {
			return trojan.New(LC.TrojanServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"trusttunnel": func(lc C.InboundListenConfig) (io.Closer, error) {
			return trusttunnel.New(LC.TrustTunnelServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"realm": func(lc C.InboundListenConfig) (io.Closer, error) {
			return hysteria2_realm.New(LC.Hysteria2RealmServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"tuic": func(lc C.InboundListenConfig) (io.Closer, error) {
			return tuic.New(LC.TuicServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key", Token: []string{"test"}}, lc, nil)
		},
		"hysteria2": func(lc C.InboundListenConfig) (io.Closer, error) {
			return sing_hysteria2.New(LC.Hysteria2Server{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"http": func(lc C.InboundListenConfig) (io.Closer, error) {
			return httpListener.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"socks": func(lc C.InboundListenConfig) (io.Closer, error) {
			return socks.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
		"mixed": func(lc C.InboundListenConfig) (io.Closer, error) {
			return mixed.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", Certificate: "cert", PrivateKey: "key"}, lc, nil)
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			baseline := certificateWorkers()
			l, err := factory(A.NewListenConfig())
			if err != nil {
				t.Fatal(err)
			}
			if got := certificateWorkers(); got != baseline+1 {
				t.Errorf("active watchers=%d, want %d", got, baseline+1)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for certificateWorkers() != baseline && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := certificateWorkers(); got != baseline {
				t.Errorf("Close retained %d certificate watchers", got-baseline)
			}
			runtime.KeepAlive(l)
			baseline = certificateWorkers()
			_, err = factory(certificateFailListen{A.NewListenConfig()})
			if !errors.Is(err, errCertificateBind) {
				t.Fatalf("did not reach bind failure: %v", err)
			}
			if got := certificateWorkers(); got != baseline {
				t.Errorf("constructor failure retained %d certificate watchers", got-baseline)
			}
		})
	}
}
