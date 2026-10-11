package validation_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"testing"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/content"
	"github.com/metacubex/mihomo/mobile/validation"
)

func TestNewSelectedScopeHasOwnCoverageAndIndependentCandidate(t *testing.T) {
	for _, link := range []string{
		"anytls://documentation@proxy.example:443?sni=tls.example&fp=chrome",
		"hy2://documentation@proxy.example:443?sni=tls.example&insecure=0",
		"vless://00000000-0000-4000-8000-000000000001@proxy.example:443?type=grpc&security=tls&sni=tls.example&serviceName=public-service",
		"anytls://documentation@proxy.example:443?sni=",
		"hy2://documentation@proxy.example:443,8443-8445?sni=192.0.2.2",
		"vless://00000000-0000-4000-8000-000000000001@proxy.example:443?type=http&security=none&host=h2.example&path=%2Fh2",
		"vless://00000000-0000-4000-8000-000000000001@proxy.example:443?type=tcp&security=tls&host=http.example&path=%2Finactive&quicSecurity=none",
		"trojan://documentation@proxy.example:443?security=tls&type=ws&host=ws.example&path=%2Fws&sni=tls.example",
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(`{"add":"proxy.example","port":443,"id":"00000000-0000-4000-8000-000000000001","aid":0,"security":"auto","net":"http"}`)),
		"proxies: [{name: Public, type: vless, server: proxy.example, port: 443, uuid: 00000000-0000-4000-8000-000000000001, tls: true, network: ws, ws-opts: {path: /ws}, ech-opts: {enable: true, query-server-name: ech.example}}]",
	} {
		inspection := content.Inspect("coverage-content", []byte(link))
		if len(inspection.Entries) != 1 || inspection.Entries[0].Status != "supported" {
			t.Fatal("public content precondition failed")
		}
		input := []byte(fmt.Sprintf("proxies: [%s]\nproxy-groups: [{name: selected-route, type: select, proxies: [selected-node]}]\nrules: ['MATCH,selected-route']\n", inspection.Entries[0].NodeJSON))
		r := validation.Validate("new-proxy-scope", input)
		if r.Category != "pass" || !slices.Contains(r.Covered, "mobile-proxy-ipv4-tcp-v2") || slices.Contains(r.Covered, "m1b-fixed-ipv4-tcp") {
			t.Fatal("expected new scope with accurate standalone coverage")
		}
		raw, err := config.UnmarshalRawConfig(input)
		if err != nil {
			t.Fatal("synthetic source did not parse")
		}
		candidate, err := config.BuildMobileSelectedCandidate(raw)
		if candidate != nil {
			defer candidate.Discard(context.Background())
		}
		if err != nil || candidate == nil || candidate.Proxies["selected-node"] == nil {
			t.Fatal("independent runtime candidate cannot reuse temporary validation objects")
		}
		if err = candidate.Discard(context.Background()); err != nil {
			t.Fatal("real candidate cleanup failed")
		}
	}
}
