package lifecycle

import (
	"github.com/metacubex/mihomo/common/lifecycle"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
)

// Certificate owns one listener's file watcher, including construction rollback.
// It reuses the same loader and resource owner as outbound TLS.
type Certificate struct{ resources lifecycle.Group }

func (c *Certificate) Load(certificate, privateKey string) (func() (*tls.Certificate, error), error) {
	loader, err := ca.NewTLSKeyPairLoaderWithOwner(certificate, privateKey, &c.resources)
	if err != nil {
		return nil, err
	}
	if err := c.resources.Activate(); err != nil {
		// Upstream still serves the loaded certificate if watching cannot start.
		// Keep that behavior; retain the failed resource for explicit cleanup.
		log.Warnln("[TLS] certificate file updates unavailable: %v", err)
	}
	return loader, nil
}

func (c *Certificate) Close() error {
	if c == nil {
		return nil
	}
	return c.resources.Close()
}
