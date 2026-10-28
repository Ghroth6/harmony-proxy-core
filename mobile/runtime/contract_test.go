package runtime_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/mobile/policy/contract"
	R "github.com/metacubex/mihomo/mobile/runtime"
)

var sample = []byte("proxies: []\n")

func TestRuntimeRequiresPreparedPolicyForEveryStart(t *testing.T) {
	var request map[string]any
	if err := json.Unmarshal([]byte(envelope()), &request); err != nil {
		t.Fatal(err)
	}
	delete(request, "preparedPolicy")
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := R.DecodeStart(2, 7, sample, encoded); err == nil {
		t.Fatal("a static validation receipt must not authorize an unprepared runtime")
	}
}

func TestRuntimeV5AcceptsExplicitAllApplicationsAndRejectsPreviousABI(t *testing.T) {
	encoded := strings.Replace(envelope(), `"applicationIds":["com.huawei.hmos.browser"]`, `"applicationScope":"all","applicationIds":[]`, 1)
	request, err := R.DecodeStart(2, 7, sample, []byte(encoded))
	if err != nil || len(request.PlatformPolicy.ApplicationIDs) != 0 {
		t.Fatalf("explicit all must be accepted by runtime v5: %v", err)
	}
	for _, version := range []string{"1", "2", "3", "4"} {
		previous := strings.Replace(encoded, `"contractVersion":5`, `"contractVersion":`+version, 1)
		if _, err = R.DecodeStart(2, 7, sample, []byte(previous)); err == nil {
			t.Fatal("previous ABI must not be admitted")
		}
	}
}

func envelope() string {
	platform := contract.Platform{RuntimeOptions: R.RuntimeOptions{Entry: "system-vpn", Transport: "tcp-udp", UDP: true}, PlatformPolicy: R.PlatformPolicy{Revision: "browser-v1", AddressFamily: "ipv4", ApplicationIDs: []string{"com.huawei.hmos.browser"}}, TunPolicy: R.TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", MTU: 1500}}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(sample))
	prepared, err := contract.Seal(digest, nil, platform, nil)
	if err != nil {
		panic(err)
	}
	request := R.StartRequest{ContractVersion: 5, OperationID: "start:1", Generation: 2, NetworkGeneration: 17, TransferID: "7", InputRevision: "policy-v1", InputDigest: digest, RuntimeOptions: platform.RuntimeOptions, PlatformPolicy: platform.PlatformPolicy, TunPolicy: platform.TunPolicy, PreparedPolicy: &prepared}
	encoded, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func TestRuntimeV5CarriesNetworkEpochAndNativeLengthRepresentation(t *testing.T) {
	request := strings.Replace(envelope(), `"networkGeneration":17`, `"networkGeneration":21`, 1)
	decoded, err := R.DecodeStart(2, 7, sample, []byte(request))
	if err != nil || decoded.NetworkGeneration != 21 || R.MaxInputBytes != 1<<31-1 {
		t.Fatal("runtime v5 must preserve the actual submitted path identity and input budget")
	}
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
		"duplicate":           strings.Replace(envelope(), `"contractVersion":5`, `"contractVersion":5,"contractVersion":5`, 1),
		"nested duplicate":    strings.Replace(envelope(), `"dns":false`, `"dns":false,"dns":false`, 1),
		"unknown":             strings.Replace(envelope(), `"contractVersion":5`, `"extra":0,"contractVersion":5`, 1),
		"old version":         strings.Replace(envelope(), `"contractVersion":5`, `"contractVersion":1`, 1),
		"missing network":     strings.Replace(envelope(), `"networkGeneration":17,`, ``, 1),
		"zero network":        strings.Replace(envelope(), `"networkGeneration":17`, `"networkGeneration":0`, 1),
		"unsafe network":      strings.Replace(envelope(), `"networkGeneration":17`, `"networkGeneration":9007199254740992`, 1),
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

func TestDecodeStartBoundedAndUTF8Values(t *testing.T) {
	for _, generation := range []uint64{0, 0x80000000, ^uint64(0)} {
		if _, err := R.DecodeStart(generation, 7, sample, []byte(envelope())); err == nil {
			t.Fatal("unbounded generation accepted")
		}
	}
	for _, request := range [][]byte{[]byte(strings.Repeat(" ", 8193)), append([]byte(envelope()), 0xff)} {
		if _, err := R.DecodeStart(2, 7, sample, request); err == nil {
			t.Fatal("unbounded or non-UTF8 request accepted")
		}
	}

	if _, err := R.DecodeStart(2, 0, sample, []byte(envelope())); err == nil {
		t.Fatal("zero transfer accepted")
	}
}
