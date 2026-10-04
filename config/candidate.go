package config

import (
	"context"

	"github.com/metacubex/mihomo/component/configresources"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Discard releases a parsed candidate which has not been published. It must not
// be used on the active configuration: executor owns retirement after Apply.
// Repeated calls (including from shallow copies) wait on the same cleanup.
func (c *Config) Discard(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.candidateResources.Close(ctx)
}

// CheckCandidate rejects a discarded or retired candidate before active
// resources are retired. Config literals have no parser-owned resources.
func (c *Config) CheckCandidate() error {
	return c.candidateResources.CheckTransfer()
}

// TransferToRuntime is called by executor immediately before publication.
// After this succeeds Discard is forbidden; runtime retirement owns cleanup.
func (c *Config) TransferToRuntime() error {
	return c.candidateResources.Transfer()
}

// SharesCandidate identifies shallow copies of the same parsed candidate.
func (c *Config) SharesCandidate(other *Config) bool {
	return c != nil && other != nil && c.candidateResources != nil && c.candidateResources == other.candidateResources
}

// RetireCandidate prevents publication after runtime retirement starts. It does
// not close resources: executor still owns cancellation, waiting and closing.
func (c *Config) RetireCandidate() {
	if c != nil {
		c.candidateResources.Retire()
	}
}

// WaitCleanup continues any retained candidate cleanup in a parse/apply error.
// The original parse/apply failure is intentionally not returned by this wait.
func WaitCleanup(ctx context.Context, err error) error {
	return configresources.WaitCleanup(ctx, err)
}

func ownProvider(owned *configresources.Set, p P.ProxyProvider) {
	owned.AddProvider(p)
	for _, proxy := range p.Proxies() {
		owned.AddProxy(proxy)
	}
}
