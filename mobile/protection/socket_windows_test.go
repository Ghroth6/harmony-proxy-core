//go:build windows

package protection_test

import "syscall"

func socketIsOpen(fd uintptr) bool {
	_, err := syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, 0x1008) // SO_TYPE
	return err == nil
}
