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
	policy "github.com/metacubex/mihomo/mobile/policy/contract"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	ContractVersion    = 2
	MaxGeneration      = 0x7fffffff
	MaxInputBytes      = 1024 * 1024
	MaxRequestBytes    = 1024 * 1024
	MaxOutputBytes     = 1024 * 1024
	PacketQueue        = 128
	MTU                = 1500
	MaxTCPTuples       = 32
	MaxUDPFlows        = 32
	MaxTransferRecords = 64
	StartObservation   = 5 * time.Second
	StopObservation    = 10 * time.Second
	StackName          = "gvisor-ipv4-tcp"
)

type RuntimeOptions = policy.RuntimeOptions
type PlatformPolicy = policy.PlatformPolicy
type TunPolicy = policy.TunPolicy
type TunIPv6Policy = policy.IPv6Policy
type StartRequest struct {
	ContractVersion   int                     `json:"contractVersion"`
	OperationID       string                  `json:"operationId"`
	Generation        uint64                  `json:"generation"`
	NetworkGeneration uint64                  `json:"networkGeneration"`
	TransferID        string                  `json:"transferId"`
	InputRevision     string                  `json:"inputRevision"`
	InputDigest       string                  `json:"inputDigest"`
	RuntimeOptions    RuntimeOptions          `json:"runtimeOptions"`
	PlatformPolicy    PlatformPolicy          `json:"platformPolicy"`
	TunPolicy         TunPolicy               `json:"tunPolicy"`
	PreparedPolicy    *policy.PreparedContext `json:"preparedPolicy,omitempty"`
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
	UDPFlows      int `json:"udpFlows,omitempty"`
	UDPPackets    int `json:"udpPackets,omitempty"`
	UDPWrites     int `json:"udpWrites,omitempty"`
	DNSWaiters    int `json:"dnsWaiters,omitempty"`
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
	if json.Unmarshal(request, &fields) != nil || !fieldsWithOptional(fields, []string{"contractVersion", "operationId", "generation", "networkGeneration", "transferId", "inputRevision", "inputDigest", "runtimeOptions", "platformPolicy", "tunPolicy"}, "preparedPolicy") {
		return fail("REQUEST_FIELDS")
	}
	for name, keys := range map[string][]string{
		"runtimeOptions": {"entry", "transport", "dns", "ipv6", "udp", "explicitListeners", "resourceDownloads"},
		"platformPolicy": {"revision", "addressFamily", "applicationIds"},
	} {
		var object map[string]json.RawMessage
		if json.Unmarshal(fields[name], &object) != nil || !exactFields(object, keys...) {
			return fail("REQUEST_FIELDS")
		}
	}
	var tunFields map[string]json.RawMessage
	if json.Unmarshal(fields["tunPolicy"], &tunFields) != nil || !fieldsWithOptional(tunFields, []string{"address", "prefixLength", "route", "routePrefixLength", "mtu"}, "ipv6", "dnsServers") {
		return fail("REQUEST_FIELDS")
	}
	if encoded, ok := tunFields["ipv6"]; ok {
		var value map[string]json.RawMessage
		if json.Unmarshal(encoded, &value) != nil || !exactFields(value, "address", "prefixLength", "route", "routePrefixLength") {
			return fail("REQUEST_FIELDS")
		}
	}
	if encoded, ok := fields["preparedPolicy"]; ok {
		if !preparedFields(encoded) {
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
	sourcePolicy := target.PreparedPolicy != nil
	if sourcePolicy && target.NetworkGeneration == 0 {
		return fail("REQUEST_IDENTITY")
	}
	if options.Entry != "system-vpn" || options.ExplicitListeners || (options.Transport != "tcp" && options.Transport != "tcp-udp") || (options.Transport == "tcp-udp") != options.UDP || (options.DNS && !options.UDP) {
		return fail("RUNTIME_OPTIONS")
	}
	if (!sourcePolicy && (options.DNS || options.IPv6 || options.UDP || options.ResourceDownloads)) || (sourcePolicy && !options.UDP) {
		return fail("RUNTIME_OPTIONS")
	}
	policy := target.PlatformPolicy
	family := "ipv4"
	if options.IPv6 {
		family = "dual"
	}
	if policy.AddressFamily != family || len(policy.ApplicationIDs) < 1 || len(policy.ApplicationIDs) > 16 {
		return fail("PLATFORM_POLICY")
	}
	seen := map[string]bool{}
	for _, id := range policy.ApplicationIDs {
		if len(id) > 128 || !bundleID.MatchString(id) || seen[id] {
			return fail("PLATFORM_POLICY")
		}
		seen[id] = true
	}
	tun := target.TunPolicy
	if tun.Address != "10.111.0.1" || tun.PrefixLength != 30 || tun.Route != "0.0.0.0" || tun.RoutePrefixLength != 0 || tun.MTU != MTU || (tun.IPv6 != nil) != options.IPv6 {
		return fail("TUN_POLICY")
	}
	if tun.IPv6 != nil && *tun.IPv6 != (TunIPv6Policy{Address: "fd00:111::1", PrefixLength: 126, Route: "::", RoutePrefixLength: 0}) {
		return fail("TUN_POLICY")
	}
	if !options.DNS && len(tun.DNSServers) != 0 {
		return fail("TUN_POLICY")
	}
	if options.DNS && (len(tun.DNSServers) != 1+boolInt(options.IPv6) || tun.DNSServers[0] != "10.111.0.2" || (options.IPv6 && tun.DNSServers[1] != "fd00:111::2")) {
		return fail("TUN_POLICY")
	}
	return target, nil
}
func preparedFields(encoded []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || !exactFields(fields, "schemaVersion", "inputDigest", "plannerVersion", "resourceManifestDigest", "resources", "platformPolicyDigest", "platform", "groupPreferencesDigest", "groupPreferences", "candidateDigest") {
		return false
	}
	for _, collection := range []struct {
		name  string
		limit int
		keys  []string
	}{{"resources", policy.MaxResources, []string{"refId", "kind", "format", "sourceDigest", "contentDigest", "byteLength", "relativePath"}}, {"groupPreferences", policy.MaxGroups, []string{"groupRef", "memberRef"}}} {
		var items []json.RawMessage
		if json.Unmarshal(fields[collection.name], &items) != nil || items == nil || len(items) > collection.limit {
			return false
		}
		for _, item := range items {
			var object map[string]json.RawMessage
			if json.Unmarshal(item, &object) != nil || !exactFields(object, collection.keys...) {
				return false
			}
		}
	}
	var platform map[string]json.RawMessage
	if json.Unmarshal(fields["platform"], &platform) != nil || !exactFields(platform, "runtimeOptions", "platformPolicy", "tunPolicy") {
		return false
	}
	for name, keys := range map[string][]string{
		"runtimeOptions": {"entry", "transport", "dns", "ipv6", "udp", "explicitListeners", "resourceDownloads"},
		"platformPolicy": {"revision", "addressFamily", "applicationIds"},
	} {
		var object map[string]json.RawMessage
		if json.Unmarshal(platform[name], &object) != nil || !exactFields(object, keys...) {
			return false
		}
	}
	var tun map[string]json.RawMessage
	if json.Unmarshal(platform["tunPolicy"], &tun) != nil || !fieldsWithOptional(tun, []string{"address", "prefixLength", "route", "routePrefixLength", "mtu"}, "ipv6", "dnsServers") {
		return false
	}
	if raw, ok := tun["ipv6"]; ok {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || !exactFields(object, "address", "prefixLength", "route", "routePrefixLength") {
			return false
		}
	}
	return true
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func fieldsWithOptional(fields map[string]json.RawMessage, required []string, optional ...string) bool {
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if raw, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, raw := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
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
