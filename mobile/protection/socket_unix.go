//go:build linux || darwin || freebsd

package protection

import "syscall"

type probeIdentity struct {
	public int64
	stat   syscall.Stat_t
	valid  bool
}

func observeProbeSocket(s probeSocket) (probeIdentity, int32) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(s), &stat); err != nil {
		return probeIdentity{public: -1}, -1
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return probeIdentity{public: -1}, 0
	}
	return probeIdentity{int64(stat.Ino), stat, true}, 1
}

func observeSameProbeSocket(s probeSocket, identity probeIdentity) int32 {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(s), &stat); err == syscall.EBADF {
		return 0
	} else if err != nil {
		return -1
	}
	if !identity.valid {
		return -1
	}
	if stat.Mode&syscall.S_IFMT == syscall.S_IFSOCK && stat.Dev == identity.stat.Dev && stat.Ino == identity.stat.Ino {
		return 1
	}
	return 0
}

func openProbeSocket() (probeSocket, func() error, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return 0, nil, err
	}
	syscall.CloseOnExec(fd)
	return probeSocket(fd), func() error { return syscall.Close(fd) }, nil
}
