package forwarding

import (
	"errors"
	"net"
)

// Match the ingress cleanup rule: an already-closed socket is harmless, but it
// must not hide a sibling failure in a protocol's aggregate Close result.
func closeError(err error) error {
	if err == nil || err == net.ErrClosed {
		return nil
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var pending []error
		for _, child := range multi.Unwrap() {
			pending = append(pending, closeError(child))
		}
		return errors.Join(pending...)
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		if child := single.Unwrap(); child != nil && closeError(child) == nil {
			return nil
		}
	}
	return err
}
