package hysteria2_realm

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/http"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/sing-quic/hysteria2/realm"
)

func TestRealmCloseEndsActiveEventStream(t *testing.T) {
	server, err := New(LC.Hysteria2RealmServer{Listen: "127.0.0.1:0", Token: "token", RealmNamePattern: DefaultRealmNamePattern}, &net.ListenConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	baseURL := "http://" + server.AddrList()[0].String()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	control, err := realm.NewControlClient(baseURL, "token", client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	registered, err := control.Register(ctx, "test", []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1234")})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/v1/test/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+registered.SessionID)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("events status=%d", response.StatusCode)
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, response.Body); done <- err }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("listener Close left the Realm HTTP event stream alive")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}
