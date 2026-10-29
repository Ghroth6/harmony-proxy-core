package vmess_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/mihomo/common/lifecycle"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gost"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/metacubex/mihomo/transport/tlsmirror"
	obfs "github.com/metacubex/mihomo/transport/v2ray-plugin"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

type ownedTLSDial func(context.Context, net.Conn, *lifecycle.Group) (net.Conn, error)

type ownedTLSRawDialer struct{ net.Conn }

func (d ownedTLSRawDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.Conn, nil
}
func (d ownedTLSRawDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, C.ErrNotSupport
}

func ownedTLSFiles(t *testing.T) tls.Certificate {
	t.Helper()
	root := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(root)
	t.Cleanup(func() { C.SetHomeDir(old) })
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"cert": cert, "key": key} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func ownedTLSClients() map[string]ownedTLSDial {
	return map[string]ownedTLSDial{
		"tls": func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
			return vmess.StreamTLSConn(ctx, raw, &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true, Certificate: "cert", PrivateKey: "key", ResourceOwner: owner})
		},
		"gost-ws": func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
			return gost.NewGostWebsocket(ctx, raw, &gost.Option{Host: "localhost", Port: "443", Path: "/ws", TLS: true, SkipCertVerify: true, Certificate: "cert", PrivateKey: "key", ResourceOwner: owner})
		},
		"v2ray-ws": func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
			return obfs.NewV2rayObfs(ctx, raw, &obfs.Option{Host: "localhost", Port: "443", Path: "/ws", TLS: true, SkipCertVerify: true, Certificate: "cert", PrivateKey: "key", ResourceOwner: owner})
		},
	}
}

func TestTLSFileClientsHandshakeAndClose(t *testing.T) {
	for name, dial := range ownedTLSClients() {
		t.Run(name, func(t *testing.T) {
			cert := ownedTLSFiles(t)
			owner := &lifecycle.Group{}
			defer owner.Close()
			if err := owner.Activate(); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			result := make(chan error, 1)
			go func() {
				for i := 0; i < 3; i++ {
					raw, err := l.Accept()
					if err != nil {
						result <- err
						return
					}
					err = func() error {
						defer raw.Close()
						_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
						c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"http/1.1"}})
						if err := c.Handshake(); err != nil {
							return err
						}
						state := c.ConnectionState()
						if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, cert.Certificate[0]) {
							return errors.New("client file certificate mismatch")
						}
						if name == "tls" {
							_, err = io.Copy(c, c)
							return err
						}
						if _, err := ws.Upgrade(c); err != nil {
							return err
						}
						b, op, err := wsutil.ReadClientData(c)
						if err != nil {
							return err
						}
						if err := wsutil.WriteServerMessage(c, op, b); err != nil {
							return err
						}
						_, _, err = wsutil.ReadClientData(c)
						var closed wsutil.ClosedError
						if errors.Is(err, io.EOF) || errors.As(err, &closed) {
							return nil
						}
						return err
					}()
					if err != nil {
						result <- err
						return
					}
				}
				result <- nil
			}()
			for i := 0; i < 3; i++ {
				raw, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				c, err := dial(ctx, raw, owner)
				cancel()
				if err != nil {
					_ = raw.Close()
					t.Fatal(err)
				}
				if _, err := c.Write([]byte("echo")); err != nil {
					_ = c.Close()
					t.Fatal(err)
				}
				b := make([]byte, 4)
				_, err = io.ReadFull(c, b)
				_ = c.Close()
				if err != nil || string(b) != "echo" {
					t.Fatalf("echo=%q err=%v", b, err)
				}
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("server did not exit")
			}
		})
	}
}

func TestTLSWrappersKeepCertificateOwner(t *testing.T) {
	ownedTLSFiles(t)
	clients := ownedTLSClients()
	clients["gost-relay"] = func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
		return gost.NewRelayDialer(ownedTLSRawDialer{raw}, &gost.RelayOption{Server: "localhost", Port: 443, TLS: true, Certificate: "cert", PrivateKey: "key", ResourceOwner: owner}).DialContext(ctx, "tcp", "127.0.0.1:80")
	}
	clients["shadowtls"] = func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
		return vmess.StreamTLSConn(ctx, raw, &vmess.TLSConfig{Host: "localhost", Certificate: "cert", PrivateKey: "key", ResourceOwner: owner, ShadowTLS: &shadowtls.Config{Version: 2, Password: "test"}})
	}
	clients["tlsmirror"] = func(ctx context.Context, raw net.Conn, owner *lifecycle.Group) (net.Conn, error) {
		return vmess.StreamTLSConn(ctx, raw, &vmess.TLSConfig{Host: "localhost", Certificate: "cert", PrivateKey: "key", ResourceOwner: owner, TLSMirror: &tlsmirror.Config{PrimaryKey: tlsmirror.GeneratePrimaryKey()}})
	}
	owner := &lifecycle.Group{}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	for name, dial := range clients {
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(100 * time.Millisecond))
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			c, err := dial(ctx, left, owner)
			if err == nil && c != nil {
				_ = c.Close()
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("lost certificate owner: %v", err)
			}
		})
	}
}
