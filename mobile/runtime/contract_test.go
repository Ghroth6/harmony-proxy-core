package runtime_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	R "github.com/metacubex/mihomo/mobile/runtime"
)

var sample = []byte("proxies: []\n")

func envelope() string {
	return fmt.Sprintf(`{"contractVersion":1,"operationId":"start:1","generation":2,"transferId":"7","inputRevision":"fixed-v1","inputDigest":"sha256:%x","runtimeOptions":{"entry":"system-vpn","transport":"tcp","dns":false,"ipv6":false,"udp":false,"explicitListeners":false,"resourceDownloads":false},"platformPolicy":{"revision":"browser-v1","addressFamily":"ipv4","applicationIds":["com.huawei.hmos.browser"]},"tunPolicy":{"address":"10.111.0.1","prefixLength":30,"route":"0.0.0.0","routePrefixLength":0,"mtu":1500}}`, sha256.Sum256(sample))
}

func TestDecodeStartFreezesExactTargetAndScalarTransfer(t *testing.T) {
	request, err := R.DecodeStart(2, 7, sample, []byte(envelope()))
	if err != nil {
		t.Fatal(err)
	}
	if request.OperationID != "start:1" || request.TransferID != "7" || request.Generation != 2 || request.TunPolicy.MTU != 1500 {
		t.Fatalf("wrong target: %+v", request)
	}
	if _, err = R.DecodeStart(2, 8, sample, []byte(envelope())); err == nil {
		t.Fatal("different scalar handoff accepted")
	}
}

func TestDecodeStartRejectsAmbiguousOrUnsupportedJSON(t *testing.T) {
	cases := map[string]string{
		"duplicate":           strings.Replace(envelope(), `"contractVersion":1`, `"contractVersion":1,"contractVersion":1`, 1),
		"nested duplicate":    strings.Replace(envelope(), `"dns":false`, `"dns":false,"dns":false`, 1),
		"unknown":             strings.Replace(envelope(), `"contractVersion":1`, `"extra":0,"contractVersion":1`, 1),
		"missing false":       strings.Replace(envelope(), `"dns":false,`, "", 1),
		"trailing":            envelope() + ` {}`,
		"zero transfer":       strings.Replace(envelope(), `"transferId":"7"`, `"transferId":"0"`, 1),
		"leading zero":        strings.Replace(envelope(), `"transferId":"7"`, `"transferId":"07"`, 1),
		"wrong mtu":           strings.Replace(envelope(), `"mtu":1500`, `"mtu":1492`, 1),
		"dns selected":        strings.Replace(envelope(), `"dns":false`, `"dns":true`, 1),
		"missing policy":      strings.Replace(envelope(), `"revision":"browser-v1",`, "", 1),
		"wrong digest":        strings.Replace(envelope(), `"inputDigest":"sha256:`, `"inputDigest":"sha256:0`, 1),
		"generation fraction": strings.Replace(envelope(), `"generation":2`, `"generation":2.0`, 1),
		"null options":        strings.Replace(envelope(), `"dns":false`, `"dns":null`, 1),
		"duplicate apps":      strings.Replace(envelope(), `["com.huawei.hmos.browser"]`, `["com.huawei.hmos.browser","com.huawei.hmos.browser"]`, 1),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := R.DecodeStart(2, 7, sample, []byte(encoded)); err == nil {
				t.Fatal("ambiguous target accepted")
			}
		})
	}
}
