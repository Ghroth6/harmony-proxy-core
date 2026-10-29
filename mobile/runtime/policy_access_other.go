//go:build !with_gvisor

package runtime

import (
	"errors"
	"github.com/metacubex/mihomo/config"
)

func (*Transfer) withPolicy(func(*config.Config) error) error { return errors.New("GVISOR_REQUIRED") }
