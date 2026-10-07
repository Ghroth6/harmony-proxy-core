//go:build linux

package runtime

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"strconv"
)

type nativeDescriptors struct{}

func DefaultDescriptorSystem() DescriptorSystem { return nativeDescriptors{} }
func (nativeDescriptors) Stat(fd int) (DescriptorMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return zeroMetadata(), err
	}
	return DescriptorMetadata{Observed: true, Device: strconv.FormatUint(uint64(stat.Dev), 10), Inode: strconv.FormatUint(stat.Ino, 10), Mode: stat.Mode, RDevice: strconv.FormatUint(uint64(stat.Rdev), 10)}, nil
}
func (nativeDescriptors) Close(fd int) error       { return unix.Close(fd) }
func (nativeDescriptors) SetNonblock(fd int) error { return unix.SetNonblock(fd, true) }
func (nativeDescriptors) NewWake() (int, int, error) {
	fds := []int{-1, -1}
	err := unix.Pipe2(fds, unix.O_CLOEXEC|unix.O_NONBLOCK)
	return fds[0], fds[1], err
}
func (nativeDescriptors) Read(fd int, b []byte) (int, error)  { return unix.Read(fd, b) }
func (nativeDescriptors) Write(fd int, b []byte) (int, error) { return unix.Write(fd, b) }
func (nativeDescriptors) Poll(ctx context.Context, fd, wake int, write bool) error {
	events := int16(unix.POLLIN)
	if write {
		events = unix.POLLOUT
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}, {Fd: int32(wake), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[1].Revents != 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			return errors.New("unexpected wake")
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("descriptor poll failed")
		}
		if poll[0].Revents&events != 0 {
			return nil
		}
	}
}
