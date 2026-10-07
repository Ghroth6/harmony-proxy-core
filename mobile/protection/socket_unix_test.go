//go:build linux || darwin || freebsd

package protection_test

import "syscall"

func socketIsOpen(fd uintptr) bool {
	_, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	return err == nil
}
