//go:build ohos

package dns

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/platformnetwork"

	D "github.com/miekg/dns"
)

// Run in a fresh process before other tests publish their snapshots:
// go test -tags ohos -run '^TestOHOSBeforeFirstSnapshot$' .../dns
func TestOHOSBeforeFirstSnapshot(t *testing.T) {
	if generation, enabled := platformnetwork.Generation(); !enabled || generation != 0 {
		t.Fatalf("requires fresh OHOS process, generation=%d enabled=%v", generation, enabled)
	}
	fallback := &forbiddenFallback{}
	client := newSystemClient()
	client.defaultNS = []dnsClient{fallback}
	query := new(D.Msg)
	query.SetQuestion("offline.test.", D.TypeA)
	if _, err := client.ExchangeContext(context.Background(), query); !errors.Is(err, ErrNoSystemDNS) || fallback.calls.Load() != 0 {
		t.Fatalf("uninitialized OHOS used native/fallback DNS: %v", err)
	}
	if interfaces, err := iface.Interfaces(); err != nil || len(interfaces) != 0 {
		t.Fatalf("uninitialized OHOS enumerated native interfaces: %+v %v", interfaces, err)
	}
}
