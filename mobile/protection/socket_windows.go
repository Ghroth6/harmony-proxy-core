package protection

import (
	"sync"
	"syscall"
)

// Like Go's net package, Winsock initialization lasts for the process. Ending
// it after each probe invalidates subsequent descriptor observations.
var winsockOnce sync.Once
var winsockErr error

// Winsock exposes socket type but no stable underlying identity here.
type probeIdentity struct{ public int64 }

func observeProbeSocket(s probeSocket) (probeIdentity, int32) {
	_, err := syscall.GetsockoptInt(syscall.Handle(s), syscall.SOL_SOCKET, 0x1008)
	if err != nil {
		return probeIdentity{-1}, -1
	}
	return probeIdentity{-1}, 1
}

func observeSameProbeSocket(_ probeSocket, _ probeIdentity) int32 {
	// This host has no stable socket cookie. Querying a closed Winsock handle
	// can also raise STATUS_INVALID_HANDLE under strict handle verification.
	return -1
}

func openProbeSocket() (probeSocket, func() error, error) {
	winsockOnce.Do(func() {
		var data syscall.WSAData
		winsockErr = syscall.WSAStartup(0x202, &data)
	})
	if winsockErr != nil {
		return 0, nil, winsockErr
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return 0, nil, err
	}
	return probeSocket(fd), func() error { return syscall.Closesocket(fd) }, nil
}
