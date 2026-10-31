// Package network submits a complete non-VPN underlying platform observation.
package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/metacubex/mihomo/component/forwarding"
	"github.com/metacubex/mihomo/component/platformnetwork"
	"github.com/metacubex/mihomo/component/resolver"
	_ "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/mobile/internal/jsonvalue"
	"github.com/metacubex/mihomo/mobile/validation"
)

const ContractVersion = 1
const MaxInputBytes = validation.MaxInputBytes // signed C.int at the native ABI
const MaxOutputBytes = 8 * 1024
const MaxSafeInteger = 9007199254740991

type Receipt struct {
	SchemaVersion int                     `json:"schemaVersion"`
	OperationID   string                  `json:"operationId"`
	Generation    uint64                  `json:"generation"`
	Category      string                  `json:"category"`
	Code          string                  `json:"code"`
	CoreIdentity  validation.CoreIdentity `json:"coreIdentity"`
}
type Controller struct{ busy func() bool }

func NewController(busy func() bool) *Controller { return &Controller{busy: busy} }

var pathMu sync.Mutex
var operationPattern = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)

// LockPath serializes a descriptor/runtime admission with a path transition.
// Runtime admissions remain short; publication holds it through the old join.
func LockPath() func() { pathMu.Lock(); return pathMu.Unlock }

type submitted struct {
	SchemaVersion int  `json:"schemaVersion"`
	VPN           bool `json:"vpn"`
	platformnetwork.Snapshot
}

func fields(value json.RawMessage, required []string, optional ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil || object == nil {
		return false
	}
	allowed := make(map[string]bool)
	for _, key := range required {
		if _, exists := object[key]; !exists {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}
func decode(input []byte) (platformnetwork.Snapshot, error) {
	invalid := errors.New("NETWORK_SNAPSHOT_INVALID")
	if len(input) == 0 || len(input) > MaxInputBytes || !utf8.Valid(input) || jsonvalue.Validate(input) != nil || !fields(input, []string{"schemaVersion", "generation", "networkId", "vpn", "online", "dns", "interfaces"}) {
		return platformnetwork.Snapshot{}, invalid
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal(input, &original)
	var interfaces []json.RawMessage
	if json.Unmarshal(original["interfaces"], &interfaces) != nil {
		return platformnetwork.Snapshot{}, invalid
	}
	for _, raw := range interfaces {
		if !fields(raw, []string{"name", "mtu", "up", "addresses", "routes"}, "index") {
			return platformnetwork.Snapshot{}, invalid
		}
		var iface map[string]json.RawMessage
		_ = json.Unmarshal(raw, &iface)
		var routes []json.RawMessage
		if json.Unmarshal(iface["routes"], &routes) != nil {
			return platformnetwork.Snapshot{}, invalid
		}
		for _, route := range routes {
			if !fields(route, []string{"destination"}, "gateway") {
				return platformnetwork.Snapshot{}, invalid
			}
		}
	}
	var value submitted
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.SchemaVersion != 1 || value.VPN || value.Generation == 0 || value.Generation > MaxSafeInteger || value.NetworkID < 0 || value.NetworkID > MaxSafeInteger {
		return platformnetwork.Snapshot{}, invalid
	}
	for _, iface := range value.Interfaces {
		if iface.Index > 0x7fffffff || iface.MTU > 65535 {
			return platformnetwork.Snapshot{}, invalid
		}
	}
	validated, err := platformnetwork.Validate(value.Snapshot)
	if err != nil {
		return platformnetwork.Snapshot{}, invalid
	}
	return validated, nil
}

func (c *Controller) Submit(operationID string, input []byte) Receipt {
	r := Receipt{SchemaVersion: 1, OperationID: operationID, Category: "invalid", Code: "NETWORK_SNAPSHOT_INVALID", CoreIdentity: validation.Identity()}
	if !operationPattern.MatchString(operationID) {
		r.Code = "NETWORK_OPERATION_INVALID"
		return r
	}
	next, err := decode(input)
	if err != nil {
		return r
	}
	r.Generation = next.Generation
	unlock := LockPath()
	defer unlock()
	if c.busy != nil && c.busy() {
		r.Category = "busy"
		r.Code = "NETWORK_RUNTIME_BUSY"
		return r
	}
	previous, _ := platformnetwork.Current()
	if next.Generation <= previous.Generation {
		r.Category = "stale"
		r.Code = "NETWORK_GENERATION_STALE"
		return r
	}
	forwarding.EnableManagementNetwork()
	forwarding.CancelManagementNetwork()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = forwarding.WaitManagementNetwork(ctx); err != nil {
		r.Category = "failure"
		r.Code = "NETWORK_EPOCH_CLEANUP"
		return r
	}
	if err = platformnetwork.Publish(next); err != nil {
		r.Category = "failure"
		r.Code = "NETWORK_PUBLISH_FAILED"
		return r
	}
	// After joining old requests, reset old connection/cache state synchronously.
	resolver.SystemResolver.ResetConnection()
	resolver.SystemResolver.ClearCache()
	if next.Online {
		if err = forwarding.ResumeManagementNetwork(); err != nil {
			r.Category = "failure"
			r.Code = "NETWORK_EPOCH_RESUME"
			return r
		}
	}
	r.Category = "published"
	r.Code = ""
	return r
}

// Accepted verifies actual core state, rather than echoing the requested epoch.
func Accepted(generation uint64) (uint64, string) {
	current, enabled := platformnetwork.Current()
	if generation == 0 || !enabled || current.Generation != generation {
		return 0, "NETWORK_GENERATION_MISMATCH"
	}
	if !current.Online {
		return 0, "NETWORK_OFFLINE"
	}
	return current.Generation, ""
}
