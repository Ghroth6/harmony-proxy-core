package adapter_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

func anyTLSRoutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "transport/anytls/util.StartRoutine.func1()")
}

func anyTLSMapping() map[string]any {
	return map[string]any{
		"name": "candidate", "type": "anytls", "server": "127.0.0.1",
		"port": 443, "password": "test", "idle-session-check-interval": 3600,
	}
}

func TestParseProxyRejectedMuxClosesAnyTLS(t *testing.T) {
	baseline := anyTLSRoutines()
	for _, tc := range []struct {
		name string
		mux  map[string]any
	}{
		{"decode", map[string]any{"enabled": true, "max-streams": []int{1, 2}}},
		{"construct", map[string]any{"enabled": true, "protocol": "invalid-protocol"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 0; attempt < 3; attempt++ {
				mapping := anyTLSMapping()
				mapping["smux"] = tc.mux
				proxy, err := adapter.ParseProxy(mapping)
				if err == nil || proxy != nil {
					if proxy != nil {
						_ = proxy.Close()
					}
					t.Fatalf("invalid smux returned proxy=%v err=%v", proxy, err)
				}
				// Check immediately, without relying on GC or the hourly timer.
				if got := anyTLSRoutines(); got != baseline {
					t.Fatalf("rejected candidate retained idle workers: got %d, baseline %d", got, baseline)
				}
			}
		})
	}
}

func TestParseProxyAcceptedAnyTLSRemainsOwned(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "plain"
		if wrapped {
			name = "smux"
		}
		t.Run(name, func(t *testing.T) {
			baseline := anyTLSRoutines()
			mapping := anyTLSMapping()
			if wrapped {
				mapping["smux"] = map[string]any{"enabled": true, "protocol": "smux"}
			}
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = proxy.Close() })
			if got := anyTLSRoutines(); got != baseline+1 {
				t.Fatalf("successful candidate lost its idle worker: got %d, baseline %d", got, baseline)
			}
			if err := proxy.Close(); err != nil {
				t.Fatal(err)
			}
			if got := anyTLSRoutines(); got != baseline {
				t.Fatalf("Close returned before idle worker ended: got %d, baseline %d", got, baseline)
			}
			if err := proxy.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseProxyConstructorErrorDoesNotCloseTypedNil(t *testing.T) {
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "invalid", "type": "wireguard", "ip": "invalid-address",
	})
	if err == nil || proxy != nil {
		t.Fatalf("invalid constructor returned proxy=%v err=%v", proxy, err)
	}
}
