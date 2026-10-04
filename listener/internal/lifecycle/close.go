package lifecycle

import (
	"errors"
	"io"
	"net"
)

// CloseError filters already-closed sockets without hiding other joined errors.
func CloseError(err error) error {
	if err == nil || err == net.ErrClosed {
		return nil
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var pending []error
		for _, child := range multi.Unwrap() {
			pending = append(pending, CloseError(child))
		}
		return errors.Join(pending...)
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		if child := single.Unwrap(); child != nil && CloseError(child) == nil {
			return nil
		}
	}
	return err
}

func Close(closer io.Closer) error {
	return CloseError(closer.Close())
}

// Rollback is deferred against a stable object and the constructor's error.
func Rollback(closer io.Closer, err *error) {
	if *err != nil {
		*err = errors.Join(*err, Close(closer))
	}
}

// CloseAll retains handles whose close failed so a later call can retry them.
func CloseAll[T io.Closer](items []T) ([]T, error) {
	remaining := items[:0]
	var pending []error
	for _, item := range items {
		if err := Close(item); err != nil {
			remaining = append(remaining, item)
			pending = append(pending, err)
		}
	}
	var zero T
	for i := len(remaining); i < len(items); i++ {
		items[i] = zero
	}
	return remaining, errors.Join(pending...)
}
