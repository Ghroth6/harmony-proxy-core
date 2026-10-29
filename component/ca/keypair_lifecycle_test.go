package ca

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/lifecycle"
	C "github.com/metacubex/mihomo/constant"
)

func keyPairWatchers() int {
	b := make([]byte, 2<<20)
	n := runtime.Stack(b, true)
	return strings.Count(string(b[:n]), "github.com/metacubex/mihomo/component/ca.(*ownedKeyPairWatcher).Start.func")
}

func TestTLSRepeatedConnectionsShareOwnedFileWatcher(t *testing.T) {
	root := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(root)
	defer C.SetHomeDir(old)
	cert, key, _, err := NewRandomTLSKeyPair(KeyPairTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"cert": cert, "key": key} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	baseline := keyPairWatchers()
	owner := &lifecycle.Group{}
	defer owner.Close()
	if err := owner.Activate(); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			cfg, err := GetTLSConfig(Option{Certificate: "cert", PrivateKey: "key", ResourceOwner: owner})
			if err == nil {
				_, err = cfg.GetClientCertificate(nil)
			}
			results <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := keyPairWatchers() - baseline; got != 1 {
		t.Fatalf("repeated connections retained %d file watchers, want 1", got)
	}
	other := &lifecycle.Group{}
	defer other.Close()
	if err := other.Activate(); err != nil {
		t.Fatal(err)
	}
	if _, err := GetTLSConfig(Option{Certificate: "cert", PrivateKey: "key", ResourceOwner: other}); err != nil {
		t.Fatal(err)
	}
	if got := keyPairWatchers() - baseline; got != 2 {
		t.Fatalf("separate owners have %d watchers, want 2", got)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if got := keyPairWatchers() - baseline; got != 1 {
		t.Fatalf("retired owner retained watcher: %d", got)
	}
	if _, err := GetTLSConfig(Option{Certificate: "cert", PrivateKey: "key", ResourceOwner: owner}); err == nil {
		t.Fatal("retired owner accepted file resource")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for keyPairWatchers() != baseline {
		if time.Now().After(deadline) {
			t.Fatal("watchers did not exit")
		}
		runtime.Gosched()
	}
}

func TestTLSWatcherCloseWaitsForReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cert")
	if err := os.WriteFile(file, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	w := &ownedKeyPairWatcher{paths: []string{file}, reload: func() { close(entered); <-release }}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer close(release)
	if err := os.WriteFile(file, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("file reload did not start")
	}
	done := make(chan error, 1)
	go func() { done <- w.Close() }()
	select {
	case <-done:
		t.Fatal("Close returned with reload still running")
	case <-time.After(20 * time.Millisecond):
	}
	// Release the callback without a second close from the deferred cleanup.
	release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join reload")
	}
}
