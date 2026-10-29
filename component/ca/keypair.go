package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/metacubex/mihomo/common/lifecycle"
	"math/big"
	"os"
	"runtime"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/fswatch"
	"github.com/metacubex/tls"
)

// NewTLSKeyPairLoader creates a loader function for TLS key pairs from the provided certificate and private key data or file paths.
// If both certificate and privateKey are empty, generates a random TLS RSA key pair.
func NewTLSKeyPairLoader(certificate, privateKey string) (func() (*tls.Certificate, error), error) {
	return newTLSKeyPairLoader(certificate, privateKey, nil)
}

// NewTLSKeyPairLoaderWithOwner keeps file watching in the caller's resource
// lifetime. The caller activates and closes the owner; inline keys need no watcher.
func NewTLSKeyPairLoaderWithOwner(certificate, privateKey string, owner *lifecycle.Group) (func() (*tls.Certificate, error), error) {
	return newTLSKeyPairLoader(certificate, privateKey, owner)
}

func newTLSKeyPairLoader(certificate, privateKey string, owner *lifecycle.Group) (func() (*tls.Certificate, error), error) {
	if certificate == "" && privateKey == "" {
		var err error
		certificate, privateKey, _, err = NewRandomTLSKeyPair(KeyPairTypeRSA)
		if err != nil {
			return nil, err
		}
	}
	cert, painTextErr := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if painTextErr == nil {
		return func() (*tls.Certificate, error) {
			return &cert, nil
		}, nil
	}

	certificate = C.Path.Resolve(certificate)
	privateKey = C.Path.Resolve(privateKey)
	var loadErr error
	if !C.Path.IsSafePath(certificate) {
		loadErr = C.Path.ErrNotSafePath(certificate)
	} else if !C.Path.IsSafePath(privateKey) {
		loadErr = C.Path.ErrNotSafePath(privateKey)
	} else {
		cert, loadErr = tls.LoadX509KeyPair(certificate, privateKey)
	}
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	updateMutex := sync.RWMutex{}
	reload := func() {
		updateMutex.Lock()
		defer updateMutex.Unlock()
		if newCert, err := tls.LoadX509KeyPair(certificate, privateKey); err == nil {
			cert = newCert
		}
	}
	get := func() (*tls.Certificate, error) {
		updateMutex.RLock()
		defer updateMutex.RUnlock()
		current := cert
		return &current, nil
	}
	if owner != nil {
		// A TLS config may be rebuilt on every connection. Share only within
		// its node's owner, so repeated handshakes do not accumulate watchers.
		type keyPairFiles struct{ certificate, privateKey string }
		resource, err := owner.GetOrAdd(keyPairFiles{certificate, privateKey}, func() lifecycle.Resource {
			return &ownedKeyPairWatcher{paths: []string{certificate, privateKey}, reload: reload, get: get}
		})
		if err != nil {
			return nil, err
		}
		return resource.(*ownedKeyPairWatcher).get, nil
	}
	// The non-owned daemon/server path retains upstream finalizer semantics.
	gcFlag := new(os.File) // A small pointer-free allocation may never run a finalizer.
	if watcher, err := fswatch.NewWatcher(fswatch.Options{Path: []string{certificate, privateKey}, Callback: func(string) { reload() }}); err == nil {
		if err = watcher.Start(); err == nil {
			runtime.SetFinalizer(gcFlag, func(f *os.File) { _ = watcher.Close() })
		}
	}
	return func() (*tls.Certificate, error) {
		defer runtime.KeepAlive(gcFlag)
		return get()
	}, nil
}

func LoadCertificates(certificate string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM([]byte(certificate)) {
		return pool, nil
	}
	painTextErr := fmt.Errorf("invalid certificate: %s", certificate)

	certificate = C.Path.Resolve(certificate)
	var loadErr error
	if !C.Path.IsSafePath(certificate) {
		loadErr = C.Path.ErrNotSafePath(certificate)
	} else {
		certPEMBlock, err := os.ReadFile(certificate)
		if pool.AppendCertsFromPEM(certPEMBlock) {
			return pool, nil
		}
		loadErr = err
	}
	if loadErr != nil {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	//TODO: support dynamic update pool too
	//      blocked by: https://github.com/golang/go/issues/64796
	//      maybe we can direct add `GetRootCAs` and `GetClientCAs` to ourselves tls fork
	return pool, nil
}

type KeyPairType string

const (
	KeyPairTypeRSA     KeyPairType = "rsa"
	KeyPairTypeP256    KeyPairType = "p256"
	KeyPairTypeP384    KeyPairType = "p384"
	KeyPairTypeEd25519 KeyPairType = "ed25519"
)

// NewRandomTLSKeyPair generates a random TLS key pair based on the specified KeyPairType and returns it with a SHA256 fingerprint.
// Note: Most browsers do not support KeyPairTypeEd25519 type of certificate, and utls.UConn will also reject this type of certificate.
func NewRandomTLSKeyPair(keyPairType KeyPairType) (certificate string, privateKey string, fingerprint string, err error) {
	var key crypto.Signer
	switch keyPairType {
	case KeyPairTypeRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyPairTypeP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyPairTypeP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyPairTypeEd25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default: // fallback to KeyPairTypeRSA
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	fingerprint = CalculateFingerprint(certDER)
	privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))
	certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return
}
