// Package policy owns the original YAML policy preparation/runtime boundary.
// Canonical values and private immutable resource inputs are separate from
// application subscription revisions and device evidence.
package policy

import (
	"errors"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/validation"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

type PreparedContext = contract.PreparedContext
type PreparedResource = contract.Resource
type Engine struct {
	root             *os.Root
	mu               sync.Mutex
	current          *resourceSession
	sessions         map[*resourceSession]struct{}
	closed           bool
	closeErr         error
	failedCloses     map[io.Closer]error
	failedCandidates map[any]error
}

var actualResourceAttempts atomic.Uint64
var resourceEventSequence atomic.Uint64

type PlanReceipt struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	OperationID       string                  `json:"operationId"`
	InputDigest       string                  `json:"inputDigest"`
	PlannerVersion    string                  `json:"plannerVersion"`
	Category          string                  `json:"category"`
	Code              string                  `json:"code"`
	ResourcesComplete bool                    `json:"resourcesComplete"`
	RuntimeDownloads  bool                    `json:"runtimeDownloads,omitempty"`
	Requirements      []contract.Requirement  `json:"requirements"`
	Groups            []contract.Group        `json:"groups"`
	GeneralIPv6       bool                    `json:"generalIPv6"`
	DNSEnabled        bool                    `json:"dnsEnabled"`
	DNSIPv6           bool                    `json:"dnsIPv6"`
	StoreSelected     bool                    `json:"storeSelected"`
	StoreFakeIP       bool                    `json:"storeFakeIP"`
	Adaptations       []contract.Adaptation   `json:"adaptations"`
	CoreIdentity      validation.CoreIdentity `json:"coreIdentity"`
}

func NewEngine(root string) (*Engine, error) {
	owned, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &Engine{root: owned, sessions: map[*resourceSession]struct{}{}, failedCloses: map[io.Closer]error{}, failedCandidates: map[any]error{}}, nil
}
func (e *Engine) Close() error {
	e.mu.Lock()
	if len(e.sessions) != 0 {
		e.mu.Unlock()
		return errors.New("POLICY_RESOURCE_OWNER_BUSY")
	}
	if e.closed || e.closeErr != nil {
		err := e.closeErr
		e.mu.Unlock()
		return err
	}
	e.closed = true
	e.mu.Unlock()
	err := e.root.Close()
	e.retainClose(e.root, err)
	return err
}
func (e *Engine) retainClose(closer io.Closer, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failedCloses[closer] = err
	e.closeErr = errors.New("POLICY_RESOURCE_CLOSE_FAILED")
}
func (e *Engine) available() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.closeErr == nil
}
func (e *Engine) retainCandidate(candidate any, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failedCandidates[candidate] = err
	e.closeErr = errors.New("POLICY_CLEANUP_FAILED")
}
func (e *Engine) ResourceAcquireCount() string {
	return strconv.FormatUint(actualResourceAttempts.Load(), 10)
}
