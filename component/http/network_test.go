package http

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/forwarding"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

type lateNetworkDialer struct {
	C.Dialer
	entered chan struct{}
	release chan struct{}
	conn    net.Conn
}

func (d *lateNetworkDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(d.entered)
	<-d.release
	return d.conn, nil
}

func TestHTTPNetworkTransitionWaitsForDetachedLateDial(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	d := &lateNetworkDialer{entered: make(chan struct{}), release: make(chan struct{}), conn: a}
	result := make(chan error, 1)
	go func() {
		_, err := HttpRequest(context.Background(), "http://127.0.0.1:9", "GET", nil, nil, WithDialer(d))
		result <- err
	}()
	<-d.entered
	forwarding.CancelManagementNetwork()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("request not canceled")
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := forwarding.WaitManagementNetwork(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forgot dial: %v", err)
	}
	close(d.release)
	waitDone, cancelDone := context.WithTimeout(context.Background(), time.Second)
	defer cancelDone()
	if err := forwarding.WaitManagementNetwork(waitDone); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("late")); err == nil {
		t.Fatal("late connection survived")
	}
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPNetworkTransitionCancelsRealBodyAndKeepsProxyPolicy(t *testing.T) {
	forwarding.EnableManagementNetwork()
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	previous := inner.GetTunnel()
	inner.New(nil)
	defer inner.New(previous)
	started := make(chan struct{})
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("partial"))
		w.(stdhttp.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	response, err := HttpRequest(context.Background(), server.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	forwarding.CancelManagementNetwork()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("canceled partial body succeeded")
	}
	_ = response.Body.Close()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := forwarding.WaitManagementNetwork(wait); err != nil {
		t.Fatal(err)
	}
	if err := forwarding.ResumeManagementNetwork(); err != nil {
		t.Fatal(err)
	}
	if _, err := HttpRequest(context.Background(), server.URL, "GET", nil, nil, WithSpecialProxy("missing")); !errors.Is(err, inner.ErrTunnelUninitialized) {
		t.Fatalf("proxy policy changed: %v", err)
	}
}
