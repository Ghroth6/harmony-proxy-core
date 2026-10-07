package protection_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/mobile/protection"
)

func TestProductionDialerRequiresProtectionOnlyForMarkedGeneration(t *testing.T) {
	var gate protection.Gate
	if got := gate.InstallDialerHook(); got != protection.Success {
		t.Fatalf("install = %d", got)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dial := func(ctx context.Context) error {
		conn, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
		if conn != nil {
			conn.Close()
		}
		return err
	}
	assertCode := func(ctx context.Context, code int32) {
		t.Helper()
		var failure protection.Error
		if err := dial(ctx); !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("dial failure = %v, want %d", err, code)
		}
	}
	assertCode(protection.WithGeneration(ctx, 1), protection.Inactive)
	if err := dial(ctx); err != nil {
		t.Fatalf("independent management: %v", err)
	}
	<-accepted
	gate.Register(1, func(generation, request uint64, fd uintptr) int32 {
		if generation != 1 || request&(1<<63) == 0 || !socketIsOpen(fd) {
			t.Error("production callback lacks live socket/identity")
		}
		return protection.PlatformFailure
	})
	assertCode(protection.WithGeneration(ctx, 1), protection.PlatformFailure)
	gate.Unregister(1)
	gate.Register(2, func(_, _ uint64, _ uintptr) int32 { return protection.Success })
	assertCode(protection.WithGeneration(ctx, 1), protection.Inactive)
	assertCode(protection.WithGeneration(ctx, 0), protection.Inactive)
	if err := dial(protection.WithGeneration(ctx, 2)); err != nil {
		t.Fatalf("protected production dial: %v", err)
	}
	<-accepted
	customCalled := false
	custom := dialer.NetDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		customCalled = true
		return nil, nil
	})
	if _, err := dialer.DialContext(protection.WithGeneration(ctx, 2), "tcp4", listener.Addr().String(), dialer.WithNetDialer(custom)); !errors.Is(err, dialer.ErrUnsupportedSocketPolicyDialer) || customCalled {
		t.Fatalf("custom transport bypass = %v, called %v", err, customCalled)
	}
	if conn, err := dialer.DialContext(protection.WithGeneration(ctx, 2), "tcp4", listener.Addr().String(), dialer.WithInterface("clashoh-absent-interface")); err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("protection bypassed explicit interface policy")
	}
	if got := gate.InstallDialerHook(); got != protection.Busy {
		t.Fatalf("hook replacement = %d", got)
	}
	gate.Unregister(2)
	assertCode(protection.WithGeneration(ctx, 2), protection.Inactive)
	select {
	case <-accepted:
		t.Fatal("failed protection connected to target")
	default:
	}
}
