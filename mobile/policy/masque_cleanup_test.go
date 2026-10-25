//go:build with_gvisor

package policy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/mobile/content"
	"github.com/metacubex/mihomo/mobile/policy"
)

func TestFailedMasquePreparationLeavesNoProtocolStackWorkers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(fmt.Sprintf("ipv6: false\ndns: {enable: false}\nproxies:\n - {name: Public, type: masque, server: 127.0.0.1, port: 443, private-key: %s, public-key: %s, ip: 10.0.0.2, remote-dns-resolve: true, dns: ['invalid-scheme://127.0.0.1'], ip-stack: {mode: gvisor}}\nrules: ['MATCH,Public']\n", base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)))
	workers := func() int {
		stack := make([]byte, 4<<20)
		n := runtime.Stack(stack, true)
		return strings.Count(string(stack[:n]), "github.com/metacubex/gvisor/pkg/tcpip/transport/tcp.(*processor).start(")
	}
	before := workers()
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if receipt := engine.Plan("masque-failed-preparation", input, nil); receipt.Category != "invalid" || receipt.Code != "PROXY_INVALID" {
			t.Fatalf("invalid node DNS must retain its actual parse error: %s/%s", receipt.Category, receipt.Code)
		}
		inspected := content.Inspect("masque-failed-content", input)
		if inspected.Category != "inspected" || len(inspected.Entries) != 1 || inspected.Entries[0].Status != "invalid" {
			t.Fatal("content inspection must retain the same failed real construction")
		}
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for workers() != before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if after := workers(); after != before {
		t.Fatalf("failed public preparation retained protocol stack workers: before=%d after=%d", before, after)
	}
}
