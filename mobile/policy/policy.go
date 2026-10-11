// Package policy owns the original YAML policy preparation/runtime boundary.
// Canonical values and private immutable resource inputs are separate from
// application subscription revisions and device evidence.
package policy

import (
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/validation"
	"os"
	"strconv"
	"sync/atomic"
)

type PreparedContext = contract.PreparedContext
type PreparedResource = contract.Resource
type Engine struct {
	root             *os.Root
	resourceAttempts atomic.Uint64
}

type PlanReceipt struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	OperationID       string                  `json:"operationId"`
	InputDigest       string                  `json:"inputDigest"`
	PlannerVersion    string                  `json:"plannerVersion"`
	Category          string                  `json:"category"`
	Code              string                  `json:"code"`
	ResourcesComplete bool                    `json:"resourcesComplete"`
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
	return &Engine{root: owned}, nil
}
func (e *Engine) Close() error { return e.root.Close() }
func (e *Engine) ResourceAcquireCount() string {
	return strconv.FormatUint(e.resourceAttempts.Load(), 10)
}
