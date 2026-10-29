package xhttp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/common/httputils"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type retainedDialConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *retainedDialConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestSharedHTTPTransportReuseAndClose(t *testing.T) {
	forwarding.Enable()
	for _, alpn := range []string{"http/1.1", "h2", "h3"} {
		t.Run(alpn, func(t *testing.T) {
			major := map[string]int{"http/1.1": 1, "h2": 2, "h3": 3}[alpn]
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != major {
					t.Errorf("HTTP version = %d, want %d", r.ProtoMajor, major)
				}
				_, _ = w.Write([]byte("data"))
			})
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = alpn == "h2"
			server.StartTLS()
			defer server.Close()
			address := server.Listener.Addr().String()
			if alpn == "h3" {
				packet, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				h3 := &http3.Server{TLSConfig: &tls.Config{Certificates: server.TLS.Certificates, NextProtos: []string{"h3"}}, Handler: handler}
				go h3.Serve(packet)
				defer h3.Close()
				address = packet.LocalAddr().String()
			}
			var dials atomic.Int32
			closed := make(chan struct{})
			var closedOnce sync.Once
			dialRaw := func(ctx context.Context) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					return nil, err
				}
				dials.Add(1)
				physical := &retainedDialConn{Conn: conn, closed: make(chan struct{})}
				stop := context.AfterFunc(ctx, func() { _ = physical.Close() })
				go func() { <-physical.closed; stop(); closedOnce.Do(func() { close(closed) }) }()
				return physical, nil
			}
			wrapTLS := func(ctx context.Context, conn net.Conn, _ bool) (net.Conn, error) {
				wrapped := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}})
				return wrapped, wrapped.HandshakeContext(ctx)
			}
			dialQUIC := func(ctx context.Context, cfg *quic.Config) (*quic.Conn, error) {
				conn, err := quic.DialAddr(ctx, address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, cfg)
				if err != nil {
					return nil, err
				}
				dials.Add(1)
				stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "dial context canceled") })
				go func() { <-conn.Context().Done(); stop(); closedOnce.Do(func() { close(closed) }) }()
				return conn, nil
			}
			transport := NewTransport(dialRaw, wrapTLS, dialQUIC, []string{alpn}, -1)
			defer httputils.CloseTransport(transport)
			for i := 0; i < 3; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+address+"/", nil)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				resp, err := transport.RoundTrip(req)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				data, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				cancel()
				if err != nil || string(data) != "data" {
					t.Fatalf("response = %q, %v", data, err)
				}
			}
			if dials.Load() != 1 {
				t.Fatalf("physical dials = %d, want 1", dials.Load())
			}
			httputils.CloseTransport(transport)
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("transport Close left connection open")
			}
		})
	}
}
