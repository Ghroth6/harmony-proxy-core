//go:build !linux

package runtime

import (
	"context"
	"errors"
)

// Production imported TUN descriptors use the Linux/OHOS syscall contract.
// Other hosts test the same owner through an explicit descriptor-system seam.
type unsupportedDescriptors struct{}

func DefaultDescriptorSystem() DescriptorSystem { return unsupportedDescriptors{} }
func (unsupportedDescriptors) Stat(int) (DescriptorMetadata, error) {
	return zeroMetadata(), errors.New("unsupported descriptor system")
}
func (unsupportedDescriptors) Close(int) error { return errors.New("unsupported descriptor system") }
func (unsupportedDescriptors) SetNonblock(int) error {
	return errors.New("unsupported descriptor system")
}
func (unsupportedDescriptors) NewWake() (int, int, error) {
	return -1, -1, errors.New("unsupported descriptor system")
}
func (unsupportedDescriptors) Read(int, []byte) (int, error) {
	return 0, errors.New("unsupported descriptor system")
}
func (unsupportedDescriptors) Write(int, []byte) (int, error) {
	return 0, errors.New("unsupported descriptor system")
}
func (unsupportedDescriptors) Poll(context.Context, int, int, bool) error {
	return errors.New("unsupported descriptor system")
}
