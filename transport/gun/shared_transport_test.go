package gun

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/transport/vmess"
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

func TestSharedTransportReusesConnectionAndCloses(t *testing.T) {
	forwarding.Enable()
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", useTLS), func(t *testing.T) {
			server := httptest.NewUnstartedServer(NewServerHandler(ServerOption{ServiceName: "shared", ConnHandler: func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}}))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			var tlsConfig *vmess.TLSConfig
			if useTLS {
				server.EnableHTTP2 = true
				server.StartTLS()
				tlsConfig = &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true, NextProtos: []string{"h2"}}
			} else {
				server.Start()
			}
			defer server.Close()
			var dials atomic.Int32
			closed := make(chan struct{})
			var closedOnce sync.Once
			transport := NewTransport(func(ctx context.Context, network, _ string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				dials.Add(1)
				physical := &retainedDialConn{Conn: conn, closed: make(chan struct{})}
				// Model a platform/inner socket retaining its construction context.
				stop := context.AfterFunc(ctx, func() { _ = physical.Close() })
				go func() { <-physical.closed; stop(); closedOnce.Do(func() { close(closed) }) }()
				return physical, nil
			}, tlsConfig, &Config{Host: strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://"), ServiceName: "shared"})
			defer transport.Close()
			echo := func(c net.Conn) {
				t.Helper()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Write([]byte("data")); err != nil {
					t.Fatal(err)
				}
				var data [4]byte
				if _, err := io.ReadFull(c, data[:]); err != nil {
					t.Fatal(err)
				}
				if string(data[:]) != "data" {
					t.Fatal("echo mismatch")
				}
			}
			first, err := transport.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			echo(first)
			second, err := transport.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			echo(second)
			_ = first.Close()
			echo(second)
			if dials.Load() != 1 {
				t.Fatalf("physical dials = %d", dials.Load())
			}
			if err := transport.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("transport Close left socket open")
			}
		})
	}
}
