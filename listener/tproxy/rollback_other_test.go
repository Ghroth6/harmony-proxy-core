//go:build !linux

package tproxy

import (
	"net"
	"testing"
)

func TestListenerLifecycleUnsupportedTProxyReleasesSocket(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := tcp.Addr().String()
	_ = tcp.Close()
	if l, err := New(address, nil); err == nil {
		_ = l.Close()
		t.Fatal("expected unsupported tproxy error")
	}
	tcp, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("failed TCP constructor leaked socket: %v", err)
	}
	_ = tcp.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address = udp.LocalAddr().String()
	_ = udp.Close()
	if l, err := NewUDP(address, nil); err == nil {
		_ = l.Close()
		t.Fatal("expected unsupported tproxy error")
	}
	udp, err = net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("failed UDP constructor leaked socket: %v", err)
	}
	_ = udp.Close()
}
