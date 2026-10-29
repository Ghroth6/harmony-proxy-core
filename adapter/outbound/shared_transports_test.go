package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/ssh"
	"github.com/metacubex/tls"
)

// Retain construction contexts as an inner/platform socket may do. Tests use
// real loopback transports, so cancellation must not be hidden by a fake pool.
type poolTestSocket struct {
	io.Closer
	once sync.Once
	done chan struct{}
}

func (s *poolTestSocket) Close() error {
	err := s.Closer.Close()
	s.once.Do(func() { close(s.done) })
	return err
}

type poolTestConn struct {
	net.Conn
	socket *poolTestSocket
}

func (c *poolTestConn) Close() error { return c.socket.Close() }

type poolTestPacket struct {
	net.PacketConn
	socket *poolTestSocket
}

func (c *poolTestPacket) Close() error { return c.socket.Close() }

type poolTestDialer struct {
	calls   atomic.Int32
	sockets chan *poolTestSocket
}

func (d *poolTestDialer) retain(ctx context.Context, c io.Closer) *poolTestSocket {
	s := &poolTestSocket{Closer: c, done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	go func() { <-s.done; stop() }()
	d.calls.Add(1)
	d.sockets <- s
	return s
}
func (d *poolTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &poolTestConn{c, d.retain(ctx, c)}, nil
}
func (d *poolTestDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	c, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &poolTestPacket{c, d.retain(ctx, c)}, nil
}
func poolTestEcho(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	var b [4]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		t.Fatal(err)
	}
	if string(b[:]) != "data" {
		t.Fatal("echo mismatch")
	}
}
func poolTestClosed(t *testing.T, d *poolTestDialer) {
	t.Helper()
	if d.calls.Load() != 1 {
		t.Fatalf("physical dials = %d", d.calls.Load())
	}
	s := <-d.sockets
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("physical socket left open")
	}
}

func TestSharedSSHTransport(t *testing.T) {
	forwarding.Enable()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		server, channels, requests, err := ssh.NewServerConn(c, config)
		if err != nil {
			done <- err
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		var handlers sync.WaitGroup
		for request := range channels {
			if request.ChannelType() != "direct-tcpip" {
				_ = request.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			channel, requests, err := request.Accept()
			if err != nil {
				continue
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer channel.Close()
				go ssh.DiscardRequests(requests)
				_, _ = io.Copy(channel, channel)
			}()
		}
		handlers.Wait()
		done <- nil
	}()
	address := l.Addr().(*net.TCPAddr)
	d := &poolTestDialer{sockets: make(chan *poolTestSocket, 8)}
	client, err := NewSsh(SshOption{BasicOption: BasicOption{DialerForAPI: d}, Server: "127.0.0.1", Port: address.Port, UserName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	guard := time.AfterFunc(5*time.Second, func() { _ = client.Close() })
	defer guard.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 80}
	first, err := client.DialContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	poolTestEcho(t, first)
	cancel()
	second, err := client.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	poolTestEcho(t, second)
	_ = first.Close()
	poolTestEcho(t, second)
	_ = client.Close()
	poolTestClosed(t, d)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH server did not exit")
	}
}

func TestSharedMasquePhysicalTransports(t *testing.T) {
	forwarding.Enable()
	for _, network := range []string{"h2", "h3", "h3-l4proxy"} {
		t.Run(network, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if r.Method == http.MethodConnect {
					var b [4]byte
					for {
						if _, err := io.ReadFull(r.Body, b[:]); err != nil {
							return
						}
						_, _ = w.Write(b[:])
						w.(http.Flusher).Flush()
					}
				} else {
					_, _ = w.Write([]byte("data"))
				}
			})
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			address := server.Listener.Addr().String()
			if network != "h2" {
				packet, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				h3 := &http3.Server{TLSConfig: &tls.Config{Certificates: server.TLS.Certificates, NextProtos: []string{"h3"}}, Handler: handler, EnableDatagrams: true}
				go h3.Serve(packet)
				defer h3.Close()
				address = packet.LocalAddr().String()
			}
			addr := netip.MustParseAddrPort(address)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			private, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			d := &poolTestDialer{sockets: make(chan *poolTestSocket, 8)}
			client, err := NewMasque(MasqueOption{BasicOption: BasicOption{DialerForAPI: d}, Server: addr.Addr().String(), Port: int(addr.Port()), Network: network, Ip: "10.0.0.2", PrivateKey: base64.StdEncoding.EncodeToString(private), PublicKey: base64.StdEncoding.EncodeToString(public), SkipCertVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if network == "h3-l4proxy" {
				first, err := client.l4Client.DialContext(ctx, "tcp", "127.0.0.1:80")
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				poolTestEcho(t, first)
				cancel()
				second, err := client.l4Client.DialContext(context.Background(), "tcp", "127.0.0.1:81")
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				poolTestEcho(t, second)
				_ = first.Close()
				poolTestEcho(t, second)
				_ = client.Close()
			} else {
				var transport http.RoundTripper
				var closeTransport func()
				if network == "h2" {
					cc, err := client.h2Transport.NewClientConn(ctx, "https", address)
					if err != nil {
						t.Fatal(err)
					}
					transport = cc
					closeTransport = func() { _ = cc.Close() }
				} else {
					pc, q, err := client.dialQuic(ctx)
					if err != nil {
						t.Fatal(err)
					}
					tr := &http3.Transport{}
					cc := tr.NewClientConn(q)
					transport = cc
					closeTransport = func() { _ = cc.CloseWithError(0, "test close"); _ = pc.Close() }
				}
				defer closeTransport()
				cancel()
				for i := 0; i < 2; i++ {
					req, err := http.NewRequest(http.MethodGet, "https://"+address+"/", nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := transport.RoundTrip(req)
					if err != nil {
						t.Fatal(err)
					}
					b, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil || string(b) != "data" {
						t.Fatalf("response = %q, %v", b, err)
					}
				}
				closeTransport()
			}
			poolTestClosed(t, d)
		})
	}
}
