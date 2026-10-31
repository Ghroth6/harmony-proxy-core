package validation_test

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/mobile/validation"
	"github.com/metacubex/mihomo/tunnel"
)

// Controlled diagnostic descent, explicitly agreed for the state and cleanup
// contract. The input still enters the same real public validation operation.
func TestValidationPreservesExistingStateAndJoinsTemporaryCleanup(t *testing.T) {
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	oldInterface, oldMark := dialer.DefaultInterface.Load(), dialer.DefaultRoutingMark.Load()
	oldIPv6, oldMode := resolver.DisableIPv6, tunnel.Mode()
	oldGeoMode, oldLoader := geodata.GeodataMode(), geodata.LoaderName()
	oldHome := C.Path.HomeDir()
	defer func() {
		tunnel.UpdateProxies(oldProxies, oldProviders)
		dialer.DefaultInterface.Store(oldInterface)
		dialer.DefaultRoutingMark.Store(oldMark)
		resolver.DisableIPv6 = oldIPv6
		tunnel.SetMode(oldMode)
		geodata.SetGeodataMode(oldGeoMode)
		geodata.SetLoader(oldLoader)
		C.SetHomeDir(oldHome)
	}()
	active := adapter.NewProxy(outbound.NewDirect())
	activeProvider, err := provider.NewCompatibleProvider("active-provider", []C.Proxy{active}, provider.NewHealthCheck([]C.Proxy{active}, "", 5000, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer activeProvider.Close()
	tunnel.UpdateProxies(map[string]C.Proxy{"active": active}, map[string]P.ProxyProvider{"active-provider": activeProvider})
	dialer.DefaultInterface.Store("existing-interface")
	dialer.DefaultRoutingMark.Store(734)
	resolver.DisableIPv6 = false
	tunnel.SetMode(tunnel.Direct)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("standard")
	material := t.TempDir()
	C.SetHomeDir(material)
	state := func() []any {
		return []any{
			fmt.Sprintf("%p", tunnel.Proxies()), tunnel.Proxies()["active"], len(tunnel.Proxies()),
			fmt.Sprintf("%p", tunnel.Providers()), tunnel.Providers()["active-provider"], len(tunnel.Providers()),
			fmt.Sprintf("%p", tunnel.Rules()), fmt.Sprintf("%p", tunnel.RuleProviders()), fmt.Sprintf("%p", tunnel.Listeners()),
			tunnel.Mode(), tunnel.Status(), tunnel.FindProcessMode(), tunnel.IsSniffing(),
			dialer.DefaultInterface.Load(), dialer.DefaultRoutingMark.Load(), dialer.GetTcpConcurrent(),
			resolver.DisableIPv6, resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver, resolver.DefaultHosts,
			geodata.GeodataMode(), geodata.LoaderName(), geodata.SiteMatcherName(),
			geodata.GeoIpUrl(), geodata.GeoSiteUrl(), geodata.MmdbUrl(), geodata.ASNUrl(),
			keepalive.KeepAliveIdle(), keepalive.KeepAliveInterval(), keepalive.DisableKeepAlive(),
			listener.GetPorts(), listener.GetTunConf(), listener.GetTuicConf(), listener.AllowLan(), listener.BindAddress(),
			C.Path.HomeDir(), C.Path.Config(), adapter.UnifiedDelay.Load(),
		}
	}
	before := state()
	ownedRoutines := func() int {
		buffer := make([]byte, 2<<20)
		n := runtime.Stack(buffer, true)
		stacks := string(buffer[:n])
		return strings.Count(stacks, "github.com/metacubex/mihomo/component/configresources.(*Set).cleanup(") +
			strings.Count(stacks, "github.com/metacubex/mihomo/adapter/provider.(*HealthCheck).process(")
	}
	beforeRoutines := ownedRoutines()
	inputs := []struct {
		bytes string
		want  string
	}{
		{staticConfig, "incomplete"},
		{strings.Replace(staticConfig, "proxies: [sample-ss, DIRECT]", "proxies: [missing, DIRECT]", 1), "incomplete"},
		{strings.Replace(staticConfig, "DOMAIN,example.com,sample-select", "DOMAIN,example.com,missing", 1), "incomplete"},
		{staticConfig + "dns:\n  enable: true\n", "incomplete"},
		{"proxies: [\n", "invalid"},
	}
	for repeat := 0; repeat < 20; repeat++ {
		for index, input := range inputs {
			result := validation.Validate(fmt.Sprintf("state-%d-%d", repeat, index), []byte(input.bytes))
			if result.Category != input.want {
				t.Fatalf("unexpected validation result: %#v", result)
			}
			if !reflect.DeepEqual(before, state()) {
				t.Fatal("validation changed existing engine globals or published configuration")
			}
			if err := activeProvider.Update(); err != nil {
				t.Fatalf("validation retired an existing provider: %v", err)
			}
		}
	}
	// No eventual GC, finalizer or health-check timer is used as cleanup proof.
	deadline := time.Now().Add(time.Second)
	for ownedRoutines() > beforeRoutines && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := ownedRoutines(); got != beforeRoutines {
		t.Fatalf("validation retained candidate/task routines: before %d, after %d", beforeRoutines, got)
	}
	entries, err := os.ReadDir(material)
	if err != nil || len(entries) != 0 {
		t.Fatalf("validation wrote configuration material: %v, %v", entries, err)
	}
}
