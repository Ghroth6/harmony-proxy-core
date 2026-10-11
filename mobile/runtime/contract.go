// Package runtime owns the single fixed IPv4/TCP mobile run and every entered
// descriptor transfer. Caller observation deadlines never cancel its cleanup.
package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/metacubex/mihomo/mobile/internal/jsonvalue"
	"github.com/metacubex/mihomo/mobile/network"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	ContractVersion    = 2
	MaxGeneration      = 0x7fffffff
	MaxInputBytes      = 1024 * 1024
	MaxRequestBytes    = 8192
	MaxOutputBytes     = 32768
	PacketQueue        = 128
	MTU                = 1500
	MaxTCPTuples       = 32
	MaxTransferRecords = 64
	StartObservation   = 5 * time.Second
	StopObservation    = 10 * time.Second
	StackName          = "gvisor-ipv4-tcp"
)

type RuntimeOptions struct {
	Entry             string `json:"entry"`
	Transport         string `json:"transport"`
	DNS               bool   `json:"dns"`
	IPv6              bool   `json:"ipv6"`
	UDP               bool   `json:"udp"`
	ExplicitListeners bool   `json:"explicitListeners"`
	ResourceDownloads bool   `json:"resourceDownloads"`
}
type PlatformPolicy struct {
	Revision       string   `json:"revision"`
	AddressFamily  string   `json:"addressFamily"`
	ApplicationIDs []string `json:"applicationIds"`
}
type TunPolicy struct {
	Address           string `json:"address"`
	PrefixLength      int    `json:"prefixLength"`
	Route             string `json:"route"`
	RoutePrefixLength int    `json:"routePrefixLength"`
	MTU               int    `json:"mtu"`
}
type StartRequest struct {
	ContractVersion   int            `json:"contractVersion"`
	OperationID       string         `json:"operationId"`
	Generation        uint64         `json:"generation"`
	NetworkGeneration uint64         `json:"networkGeneration"`
	TransferID        string         `json:"transferId"`
	InputRevision     string         `json:"inputRevision"`
	InputDigest       string         `json:"inputDigest"`
	RuntimeOptions    RuntimeOptions `json:"runtimeOptions"`
	PlatformPolicy    PlatformPolicy `json:"platformPolicy"`
	TunPolicy         TunPolicy      `json:"tunPolicy"`
}

// DescriptorMetadata is stat metadata, not an open-file-description identity.
// Decimal strings preserve the full native integer without JSON rounding.
type DescriptorMetadata struct {
	Observed bool   `json:"observed"`
	Device   string `json:"device"`
	Inode    string `json:"inode"`
	Mode     uint32 `json:"mode"`
	RDevice  string `json:"rdevice"`
}
type TunReceipt struct {
	FD             int                `json:"fd"`
	MetadataBefore DescriptorMetadata `json:"metadataBefore"`
	CloseAttempted bool               `json:"closeAttempted"`
	CloseResult    int                `json:"closeResult"`
	AfterClose     string             `json:"afterClose"`
	MetadataAfter  DescriptorMetadata `json:"metadataAfter"`
}
type ResourceReceipt struct {
	Kind        string `json:"kind"`
	State       string `json:"state"`
	CloseResult int    `json:"closeResult"`
}
type PendingOwners struct {
	Pumps         int `json:"pumps"`
	TCPCallbacks  int `json:"tcpCallbacks"`
	Constructions int `json:"constructions"`
	Forwarding    int `json:"forwarding"`
}
type ConnectionObservation struct {
	Sequence   uint64 `json:"sequence"`
	TargetIPv4 string `json:"targetIPv4"`
	TargetPort uint16 `json:"targetPort"`
	Rule       string `json:"rule"`
	Node       string `json:"node"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
}
type Receipt struct {
	ContractVersion   int                     `json:"contractVersion"`
	OperationID       string                  `json:"operationId"`
	Generation        uint64                  `json:"generation"`
	NetworkGeneration uint64                  `json:"networkGeneration"`
	TransferID        string                  `json:"transferId"`
	TransferConsumed  bool                    `json:"transferConsumed"`
	TransferState     string                  `json:"transferState"`
	OwnershipFault    bool                    `json:"ownershipFault"`
	CandidateDigest   string                  `json:"candidateDigest"`
	Phase             string                  `json:"phase"`
	Outcome           string                  `json:"outcome"`
	Cleanup           string                  `json:"cleanup"`
	FailureCode       string                  `json:"failureCode"`
	Stack             string                  `json:"stack"`
	MTU               int                     `json:"mtu"`
	ForwardingActive  bool                    `json:"forwardingActive"`
	Tun               TunReceipt              `json:"tun"`
	Resources         []ResourceReceipt       `json:"resources"`
	PendingOwners     PendingOwners           `json:"pendingOwners"`
	Connections       []ConnectionObservation `json:"connections"`
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
var bundleID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){1,15}$`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DecodeStart validates only immutable values. Resource admission and the real
// independent Mihomo validation belong to Start, after it consumes the fd.
// Errors are fixed codes: parser text or configuration bytes never escape.
func DecodeStart(generation, transferID uint64, input, request []byte) (StartRequest, error) {
	var target StartRequest
	fail := func(code string) (StartRequest, error) { return StartRequest{}, errors.New(code) }
	if generation == 0 || generation > MaxGeneration || transferID == 0 || len(input) == 0 || len(input) > MaxInputBytes || len(request) == 0 || len(request) > MaxRequestBytes || !utf8.Valid(request) {
		return fail("REQUEST_BOUNDS")
	}
	if err := jsonvalue.Validate(request); err != nil {
		return fail("REQUEST_JSON")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(request, &fields) != nil || !exactFields(fields, "contractVersion", "operationId", "generation", "networkGeneration", "transferId", "inputRevision", "inputDigest", "runtimeOptions", "platformPolicy", "tunPolicy") {
		return fail("REQUEST_FIELDS")
	}
	for name, keys := range map[string][]string{
		"runtimeOptions": {"entry", "transport", "dns", "ipv6", "udp", "explicitListeners", "resourceDownloads"},
		"platformPolicy": {"revision", "addressFamily", "applicationIds"},
		"tunPolicy":      {"address", "prefixLength", "route", "routePrefixLength", "mtu"},
	} {
		var object map[string]json.RawMessage
		if json.Unmarshal(fields[name], &object) != nil || !exactFields(object, keys...) {
			return fail("REQUEST_FIELDS")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(request))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&target) != nil {
		return fail("REQUEST_FIELDS")
	}
	if target.ContractVersion != ContractVersion || target.Generation != generation || target.NetworkGeneration > network.MaxSafeInteger || target.TransferID != strconv.FormatUint(transferID, 10) {
		return fail("REQUEST_IDENTITY")
	}
	if !safeID.MatchString(target.OperationID) || !safeID.MatchString(target.InputRevision) || !safeID.MatchString(target.PlatformPolicy.Revision) || !digest.MatchString(target.InputDigest) {
		return fail("REQUEST_IDENTITY")
	}
	actual := sha256.Sum256(input)
	if target.InputDigest != "sha256:"+hex.EncodeToString(actual[:]) {
		return fail("INPUT_DIGEST")
	}
	options := target.RuntimeOptions
	if options.Entry != "system-vpn" || options.Transport != "tcp" || options.DNS || options.IPv6 || options.UDP || options.ExplicitListeners || options.ResourceDownloads {
		return fail("RUNTIME_OPTIONS")
	}
	policy := target.PlatformPolicy
	if policy.AddressFamily != "ipv4" || len(policy.ApplicationIDs) < 1 || len(policy.ApplicationIDs) > 16 {
		return fail("PLATFORM_POLICY")
	}
	seen := map[string]bool{}
	for _, id := range policy.ApplicationIDs {
		if len(id) > 128 || !bundleID.MatchString(id) || seen[id] {
			return fail("PLATFORM_POLICY")
		}
		seen[id] = true
	}
	if target.TunPolicy != (TunPolicy{Address: "10.111.0.1", PrefixLength: 30, Route: "0.0.0.0", RoutePrefixLength: 0, MTU: MTU}) {
		return fail("TUN_POLICY")
	}
	return target, nil
}
func exactFields(fields map[string]json.RawMessage, keys ...string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}
func strictJSON(encoded []byte) error {
	return jsonvalue.Validate(encoded)
}
