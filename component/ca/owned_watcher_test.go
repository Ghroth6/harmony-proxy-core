package ca

import (
	"bytes"
	"github.com/metacubex/mihomo/common/lifecycle"
	C "github.com/metacubex/mihomo/constant"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOwnedTLSFilesActivateReloadAndJoinBeforeRetirement(t *testing.T) {
	root := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(root)
	defer C.SetHomeDir(old)
	cert, key, _, err := NewRandomTLSKeyPair(KeyPairTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	write := func(cert, key string) {
		if err := os.WriteFile(filepath.Join(root, "cert"), []byte(cert), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "key"), []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cert, key)
	owner := &lifecycle.Group{}
	defer owner.Close()
	get, err := newTLSKeyPairLoader("cert", "key", owner)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := get()
	nextCert, nextKey, _, err := NewRandomTLSKeyPair(KeyPairTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	write(nextCert, nextKey)
	time.Sleep(100 * time.Millisecond)
	if current, _ := get(); !bytes.Equal(current.Certificate[0], first.Certificate[0]) {
		t.Fatal("preparation activated a file watcher")
	}
	if err := owner.Activate(); err != nil {
		t.Fatal(err)
	}
	write(nextCert, nextKey)
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, _ := get()
		if !bytes.Equal(current.Certificate[0], first.Certificate[0]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("active certificate did not reload")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	current, _ := get()
	write(cert, key)
	time.Sleep(150 * time.Millisecond)
	if after, _ := get(); !bytes.Equal(after.Certificate[0], current.Certificate[0]) {
		t.Fatal("retired watcher changed certificate")
	}
}
