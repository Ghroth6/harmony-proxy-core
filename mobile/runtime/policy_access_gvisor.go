//go:build with_gvisor

package runtime

import "github.com/metacubex/mihomo/config"

func (t *Transfer) withPolicy(action func(*config.Config) error) error { return action(t.engine.cfg) }
