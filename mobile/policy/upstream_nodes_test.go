package policy_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/transport/socks5"
)

func TestOriginalPolicyKeepsRealNodeFileReadsAndOwnsDeferredTLSWatcher(t *testing.T) {
	root := t.TempDir()
	oldRoot := C.Path.HomeDir()
	C.SetHomeDir(root)
	defer C.SetHomeDir(oldRoot)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(root, "node.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600) != nil {
		t.Fatal("fixture key write")
	}
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(root, "tls.crt"), []byte(certificate), 0600) != nil || os.WriteFile(filepath.Join(root, "tls.key"), []byte(privateKey), 0600) != nil {
		t.Fatal("fixture TLS files write")
	}
	for _, item := range []struct{ name, node, category, code string }{
		{"read-key", "{name: Public, type: ssh, server: 127.0.0.1, port: 22, username: public, private-key: ./node.key}", "planned", ""},
		{"missing-key", "{name: Public, type: ssh, server: 127.0.0.1, port: 22, username: public, private-key: ./missing.key}", "invalid", "PROXY_INVALID"},
		{"missing-tls-file", "{name: Public, type: socks5, server: 127.0.0.1, port: 1080, tls: true, certificate: ./missing.crt, private-key: ./missing.key}", "invalid", "PROXY_INVALID"},
		{"watcher-owner", "{name: Public, type: socks5, server: 127.0.0.1, port: 1080, tls: true, certificate: ./tls.crt, private-key: ./tls.key}", "planned", ""},
	} {
		t.Run(item.name, func(t *testing.T) {
			engine, err := policy.NewEngine(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			input := []byte("ipv6: false\ndns: {enable: false}\nproxies:\n - " + item.node + "\nrules: ['MATCH,Public']\n")
			plan := engine.Plan("upstream-node-file", input, nil)
			if plan.Category != item.category || plan.Code != item.code {
				t.Fatalf("actual file operation: %s/%s", plan.Category, plan.Code)
			}
		})
	}
}

func TestUpstreamStaticConstructionDoesNotMakeInvalidPhysicalPortForwardable(t *testing.T) {
	input := []byte("ipv6: false\ndns: {enable: false}\nproxies:\n - {name: Public, type: trojan, server: 127.0.0.1, port: 65536, password: documentation-only, sni: node.example.invalid}\nrules: ['MATCH,Public']\n")
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	prepared, err := contract.Seal(contract.Digest(input), nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var protected atomic.Int32
	root, _ := activatePublicPolicy(t, cfg, []string{}, &protected)
	ctx, cancel := context.WithTimeout(root, time.Second)
	defer cancel()
	conn, err := cfg.Proxies["Public"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "destination.invalid", DstPort: 443})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("an invalid physical port returned a connection")
	}
	if err == nil || protected.Load() != 0 {
		t.Fatal("invalid physical port must fail before a socket can be connected or protected")
	}
}

// Each peer authenticates and observes its own actual SOCKS request. The entry
// relays to the exit; the exit serves a destination that cannot be dialed locally.
func TestOriginalPolicyAuthenticatedSOCKSChainUsesDeclaredDialerProxy(t *testing.T) {
	exit, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	entry, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	results := make(chan error, 2)
	serve := func(listener net.Listener, user, password, target string, relay bool) {
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			addr, command, authenticated, err := socks5.ServerHandshake(conn, auth.NewAuthenticator([]auth.AuthUser{{User: user, Pass: password}}))
			if err != nil {
				results <- err
				return
			}
			if addr.String() != target || command != socks5.CmdConnect || authenticated != user {
				results <- fmt.Errorf("declared SOCKS hop, destination or authentication changed")
				return
			}
			if relay {
				next, err := net.DialTimeout("tcp4", target, time.Second)
				if err != nil {
					results <- err
					return
				}
				defer next.Close()
				copied := make(chan error, 1)
				go func() { _, err := io.Copy(next, conn); copied <- err }()
				_, err = io.Copy(conn, next)
				_ = conn.Close()
				_ = next.Close()
				<-copied
				results <- err
				return
			}
			payload := make([]byte, len("chain-request"))
			if _, err = io.ReadFull(conn, payload); err == nil && string(payload) != "chain-request" {
				err = fmt.Errorf("chain payload changed")
			}
			if err == nil {
				_, err = conn.Write([]byte("chain-answer"))
			}
			results <- err
		}()
	}
	serve(entry, "entry-user", "entry-password", exit.Addr().String(), true)
	serve(exit, "exit-user", "exit-password", "destination.invalid:443", false)
	input := []byte(fmt.Sprintf(`ipv6: false
dns: {enable: false}
proxies:
 - {name: Entry, type: socks5, server: 127.0.0.1, port: %d, username: entry-user, password: entry-password, ip-version: ipv4}
 - {name: Exit, type: socks5, server: 127.0.0.1, port: %d, username: exit-user, password: exit-password, dialer-proxy: Entry}
proxy-groups:
 - {name: PublicSelect, type: select, proxies: [Exit]}
rules: ['MATCH,PublicSelect']
`, entry.Addr().(*net.TCPAddr).Port, exit.Addr().(*net.TCPAddr).Port))
	engine, err := policy.NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	plan := engine.Plan("upstream-chain-plan", input, nil)
	if plan.Category != "planned" || !plan.ResourcesComplete {
		t.Fatalf("upstream SOCKS5 chain was refused: %s/%s", plan.Category, plan.Code)
	}
	prepared, err := contract.Seal(contract.Digest(input), nil, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation := engine.Validate("upstream-chain-validate", input, prepared); validation.Category != "pass" {
		t.Fatalf("upstream SOCKS5 construction: %s/%s", validation.Category, validation.Code)
	}
	cfg, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := cfg.Proxies["Exit"].DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "destination.invalid", DstPort: 443}); err == nil || conn != nil {
		t.Fatal("prepared chain opened network before activation")
	}
	var protected atomic.Int32
	root, _ := activatePublicPolicy(t, cfg, []string{"127.0.0.1"}, &protected)
	ctx, cancel := context.WithTimeout(root, 3*time.Second)
	defer cancel()
	conn, err := cfg.Proxies["PublicSelect"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "destination.invalid", DstPort: 443})
	if err != nil {
		t.Fatalf("declared two-hop SOCKS chain: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("chain-request")); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, len("chain-answer"))
	if _, err = io.ReadFull(conn, answer); err != nil || string(answer) != "chain-answer" {
		t.Fatalf("authenticated chain answer: %v", err)
	}
	_ = conn.Close()
	for n := 0; n < 2; n++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("chain peer did not join")
		}
	}
	if protected.Load() != 1 {
		t.Fatalf("one real client physical connection must be protected, got %d", protected.Load())
	}
}
