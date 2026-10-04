package http_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
)

type observedListenConfig struct {
	C.InboundListenConfig
	address  string
	closeErr error
}

func (c *observedListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := c.InboundListenConfig.Listen(ctx, network, address)
	if err == nil {
		c.address = l.Addr().String()
		if c.closeErr != nil {
			l = &closeErrorListener{Listener: l, err: c.closeErr}
		}
	}
	return l, err
}

type closeErrorListener struct {
	net.Listener
	err error
}

func (l *closeErrorListener) Close() error {
	return errors.Join(l.Listener.Close(), l.err)
}

func TestListenerLifecycleRollbackReportsCloseFailure(t *testing.T) {
	want := errors.New("synthetic close failure")
	lc := &observedListenConfig{InboundListenConfig: A.NewListenConfig(), closeErr: want}
	_, err := http.NewWithConfig(LC.AuthServer{Listen: "127.0.0.1:0", Certificate: "missing-test-certificate.pem", PrivateKey: "missing-test-key.pem"}, lc, nil)
	if !errors.Is(err, want) {
		t.Fatalf("rollback close failure was swallowed: %v", err)
	}
	rebound, err := net.Listen("tcp", lc.address)
	if err != nil {
		t.Fatal(err)
	}
	_ = rebound.Close()
}

func TestListenerLifecycleTLSFailureReleasesSocket(t *testing.T) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	constructors := map[string]func(LC.AuthServer, C.InboundListenConfig) (C.Listener, error){
		"http": func(c LC.AuthServer, lc C.InboundListenConfig) (C.Listener, error) {
			l, err := http.NewWithConfig(c, lc, nil)
			if err != nil {
				return nil, err
			}
			return l, nil
		},
		"socks": func(c LC.AuthServer, lc C.InboundListenConfig) (C.Listener, error) {
			l, err := socks.NewWithConfig(c, lc, nil)
			if err != nil {
				return nil, err
			}
			return l, nil
		},
		"mixed": func(c LC.AuthServer, lc C.InboundListenConfig) (C.Listener, error) {
			l, err := mixed.NewWithConfig(c, lc, nil)
			if err != nil {
				return nil, err
			}
			return l, nil
		},
	}
	for name, construct := range constructors {
		for _, failure := range []string{"certificate", "ech", "client-auth", "reality"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				config := LC.AuthServer{Listen: "127.0.0.1:0"}
				switch failure {
				case "certificate":
					config.Certificate, config.PrivateKey = "missing-test-certificate.pem", "missing-test-key.pem"
				case "ech":
					config.Certificate, config.PrivateKey, config.EchKey = cert, key, "invalid-ech-key"
				case "client-auth":
					config.ClientAuthType, config.ClientAuthCert = "require-and-verify-client-cert", "invalid-client-certificate"
				case "reality":
					config.RealityConfig.PrivateKey = "invalid-reality-key"
				}
				lc := &observedListenConfig{InboundListenConfig: A.NewListenConfig()}
				l, err := construct(config, lc)
				if l != nil {
					_ = l.Close()
				}
				if err == nil {
					t.Fatal("invalid TLS settings unexpectedly accepted")
				}
				if lc.address == "" {
					t.Fatal("failure was not exercised after actual socket bind")
				}
				rebound, err := net.Listen("tcp", lc.address)
				if err != nil {
					t.Fatalf("constructor leaked %s: %v", lc.address, err)
				}
				_ = rebound.Close()
				if !strings.HasPrefix(lc.address, "127.0.0.1:") {
					t.Fatalf("unexpected address %s", lc.address)
				}
			})
		}
	}
}
