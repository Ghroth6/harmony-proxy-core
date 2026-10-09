package log

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/metacubex/tls"
)

// The mobile sink accepts bounded enum/scalar facts, never upstream format
// strings, error text, metadata, node names or configuration content.
type MobileStage uint8

const (
	StageConstructing MobileStage = iota + 1
	StageStarting
	StageRunning
	StageStopping
	StageStopped
	StageCleanupFailed
	StageRuntimeFailed
	StagePhysicalDial
	StageProtect
	StageTLS
	StageTrojanHeader
	StageInitialWrite
	StageForwardDial
	StageTunRead
	StageTunWrite
)

var mobileStages = [...]string{"", "constructing", "starting", "running", "stopping", "stopped", "cleanup-failed", "runtime-failed", "physical-dial", "protect", "tls-handshake", "trojan-header", "initial-write", "forward-dial", "tun-read", "tun-write"}

type MobileClass uint8

const (
	ClassNone MobileClass = iota
	ClassUnknown
	ClassTimeout
	ClassCanceled
	ClassEOF
	ClassSyscall
	ClassCertAuthority
	ClassCertName
	ClassCertValidity
	ClassCertInvalid
	ClassTLSRecord
	ClassProtection
)

var mobileClasses = [...]string{"none", "unknown", "timeout", "canceled", "eof", "syscall", "cert-authority", "cert-name", "cert-validity", "cert-invalid", "tls-record", "protection"}

type MobileEvent struct {
	Stage      MobileStage
	Class      MobileClass
	Errno      uint32
	Generation uint64
}

func (e MobileEvent) valid() bool {
	return e.Stage > 0 && int(e.Stage) < len(mobileStages) && int(e.Class) < len(mobileClasses) && e.Generation > 0 && e.Generation <= 0x7fffffff
}
func (e MobileEvent) String() string {
	if !e.valid() {
		return "invalid-mobile-event"
	}
	return fmt.Sprintf("stage=%s class=%s errno=%d generation=%d", mobileStages[e.Stage], mobileClasses[e.Class], e.Errno, e.Generation)
}

// WriteMobileEvent is the synchronous system-log boundary. Implementations
// must be concurrency safe and must not retain engine/platform resources.
type MobileOutput interface{ WriteMobileEvent(MobileEvent) }
type mobileOutputSlot struct{ output MobileOutput }

var mobileOutput atomic.Pointer[mobileOutputSlot]

// InstallMobileOutput is process initialization only. It is immutable once
// installed; stopping a runtime does not reopen raw logging or close the sink.
func InstallMobileOutput(output MobileOutput) bool {
	if output == nil {
		return false
	}
	return mobileOutput.CompareAndSwap(nil, &mobileOutputSlot{output: output})
}
func MobileEnabled() bool { return mobileOutput.Load() != nil }
func MobilePhase(generation uint64, stage MobileStage) {
	emitMobile(MobileEvent{Stage: stage, Class: ClassNone, Generation: generation})
}
func emitMobile(event MobileEvent) {
	if output := mobileOutput.Load(); output != nil && event.valid() {
		output.output.WriteMobileEvent(event)
	}
}

type mobileStageError struct {
	stage MobileStage
	err   error
}

func (e *mobileStageError) Error() string { return e.err.Error() }
func (e *mobileStageError) Unwrap() error { return e.err }

// Preserve the deepest truthful failed operation and original error identity.
// Standalone daemon calls keep their original error object and text unchanged.
func MarkMobileError(stage MobileStage, err error) error {
	if err == nil || !MobileEnabled() {
		return err
	}
	var marked *mobileStageError
	if errors.As(err, &marked) {
		return err
	}
	return &mobileStageError{stage: stage, err: err}
}
func MobileFailure(generation uint64, fallback MobileStage, err error) {
	if !MobileEnabled() {
		return
	}
	event := MobileEvent{Stage: fallback, Class: ClassUnknown, Generation: generation}
	var marked *mobileStageError
	if errors.As(err, &marked) {
		event.Stage = marked.stage
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		event.Errno = uint32(number)
		event.Class = ClassSyscall
	}
	var authority x509.UnknownAuthorityError
	var name x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	var timeout net.Error
	var protection interface{ MobileProtectionStatus() int32 }
	switch {
	case errors.As(err, &protection):
		event.Stage = StageProtect
		event.Class = ClassProtection
	case errors.Is(err, context.Canceled):
		event.Class = ClassCanceled
	case errors.Is(err, context.DeadlineExceeded):
		event.Class = ClassTimeout
	case errors.As(err, &authority):
		event.Class = ClassCertAuthority
	case errors.As(err, &name):
		event.Class = ClassCertName
	case errors.As(err, &invalid):
		event.Class = ClassCertInvalid
		if invalid.Reason == x509.Expired {
			event.Class = ClassCertValidity
		}
	case errors.As(err, &record):
		event.Class = ClassTLSRecord
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		event.Class = ClassEOF
	case errors.As(err, &timeout) && timeout.Timeout():
		event.Class = ClassTimeout
	}
	emitMobile(event)
}
