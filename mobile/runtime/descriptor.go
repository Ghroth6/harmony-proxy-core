package runtime

import (
	"context"
	"errors"
	"sync"
	"syscall"
)

// DescriptorSystem is the operating-system syscall boundary. Poll must return
// when its context is cancelled even if wake writing fails; no caller timeout
// transfers ownership away from the worker using this interface.
type DescriptorSystem interface {
	Stat(int) (DescriptorMetadata, error)
	Close(int) error
	SetNonblock(int) error
	NewWake() (readFD, writeFD int, err error)
	Read(int, []byte) (int, error)
	Write(int, []byte) (int, error)
	Poll(context.Context, int, int, bool) error
}
type descriptorOwner struct {
	system        DescriptorSystem
	fd            int
	before        DescriptorMetadata
	valid         bool
	mu            sync.Mutex
	attempted     bool
	result        int
	after         string
	metadataAfter DescriptorMetadata
}

func consumeDescriptor(system DescriptorSystem, fd int) *descriptorOwner {
	metadata, err := system.Stat(fd)
	return &descriptorOwner{system: system, fd: fd, before: metadata, valid: err == nil && metadata.Observed, result: -1, after: "not-observed"}
}
func zeroMetadata() DescriptorMetadata {
	return DescriptorMetadata{Device: "0", Inode: "0", RDevice: "0"}
}
func errno(err error) int {
	if err == nil {
		return 0
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		return int(number)
	}
	return 1
}
func (o *descriptorOwner) close() {
	o.mu.Lock()
	if o.attempted || !o.valid {
		o.mu.Unlock()
		return
	}
	o.attempted = true
	o.mu.Unlock()
	// The exact supplied descriptor is owned, and no retry occurs even on error.
	// Metadata is observation only: it cannot distinguish two TUN open files.
	result := errno(o.system.Close(o.fd))
	metadata, err := o.system.Stat(o.fd)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.result = result
	if err != nil {
		if errors.Is(err, syscall.EBADF) {
			o.after = "not-visible"
		} else {
			o.after = "unknown"
		}
		o.metadataAfter = zeroMetadata()
		return
	}
	o.metadataAfter = metadata
	if !metadata.Observed {
		o.after = "unknown"
	} else if metadata == o.before {
		o.after = "metadata-same"
	} else {
		o.after = "metadata-different"
	}
}
func (o *descriptorOwner) receipt() TunReceipt {
	o.mu.Lock()
	defer o.mu.Unlock()
	before, after := o.before, o.metadataAfter
	if !before.Observed {
		before = zeroMetadata()
	}
	if !after.Observed {
		after = zeroMetadata()
	}
	return TunReceipt{FD: o.fd, MetadataBefore: before, CloseAttempted: o.attempted, CloseResult: o.result, AfterClose: o.after, MetadataAfter: after}
}
