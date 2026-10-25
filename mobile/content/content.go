// Package content inspects private subscription bytes without acquiring network
// or runtime resources. Display data and canonical nodes are value snapshots.
package content

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/validation"
)

const (
	ContractVersion   = 1
	MaxInputBytes     = 1024 * 1024
	MaxEntries        = 4096
	MaxOutputBytes    = 8 * 1024 * 1024
	NormalizerVersion = "mobile-content-1"
)

var operationPattern = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
var protocolPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var linkPattern = regexp.MustCompile(`(?m)^[A-Za-z][A-Za-z0-9+.-]*://`)

// Inspector's observer is the preparation network boundary: an attempted dial
// is reported and always denied, never delegated to a caller's real network.
type Inspector struct{ networkObserver func() }

func NewInspector(networkObserver func()) *Inspector {
	return &Inspector{networkObserver: networkObserver}
}
func (i *Inspector) Inspect(operationID string, input []byte) Receipt {
	return i.inspect(operationID, input)
}

type Entry struct {
	Position        int    `json:"position"`
	DisplayName     string `json:"displayName"`
	Protocol        string `json:"protocol"`
	Status          string `json:"status"`
	Code            string `json:"code"`
	EntryDigest     string `json:"entryDigest"`
	NodeJSON        string `json:"nodeJson,omitempty"`
	CanonicalDigest string `json:"canonicalDigest,omitempty"`
}
type Receipt struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	OperationID       string                  `json:"operationId"`
	InputDigest       string                  `json:"inputDigest"`
	NormalizerVersion string                  `json:"normalizerVersion"`
	Kind              string                  `json:"kind"`
	Category          string                  `json:"category"`
	Code              string                  `json:"code"`
	Entries           []Entry                 `json:"entries"`
	CoreIdentity      validation.CoreIdentity `json:"coreIdentity"`
}

func digest(input []byte) string {
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Inspect(operationID string, input []byte) Receipt {
	return NewInspector(nil).Inspect(operationID, input)
}
func (i *Inspector) inspect(operationID string, input []byte) (receipt Receipt) {
	receipt = Receipt{SchemaVersion: 1, OperationID: operationID, InputDigest: digest(input), NormalizerVersion: NormalizerVersion, Kind: "unknown", Category: "failure", Entries: []Entry{}, CoreIdentity: validation.Identity()}
	fail := func(category, code string) Receipt {
		receipt.Category = category
		receipt.Code = code
		receipt.Entries = []Entry{}
		return receipt
	}
	defer func() {
		if recover() != nil {
			receipt = fail("failure", "CONTENT_FAILURE")
		}
	}()
	if !operationPattern.MatchString(operationID) || len(input) > MaxInputBytes {
		return fail("failure", "REQUEST_BOUNDS")
	}
	if !utf8.Valid(input) {
		return fail("invalid", "CONTENT_UTF8_INVALID")
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(input), "\ufeff"))
	if text == "" {
		return fail("invalid", "CONTENT_EMPTY")
	}
	if linkPattern.MatchString(text) {
		receipt.Kind = "nodes"
	} else {
		compact := strings.Join(strings.Fields(text), "")
		decoded, err := decodeBase64(compact)
		if err == nil && utf8.Valid(decoded) && linkPattern.MatchString(strings.TrimSpace(string(decoded))) {
			if len(decoded) > MaxInputBytes {
				return fail("failure", "CONTENT_DECODED_BOUNDS")
			}
			text = strings.TrimSpace(string(decoded))
			receipt.Kind = "base64-nodes"
		} else {
			var code string
			receipt.Kind = "yaml"
			receipt.Entries, code = i.inspectYAML([]byte(text))
			if code != "" {
				category := "invalid"
				if strings.HasSuffix(code, "BOUNDS") {
					category = "failure"
				}
				return fail(category, code)
			}
			return boundedReceipt(receipt)
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if len(receipt.Entries) == MaxEntries {
			return fail("failure", "CONTENT_ENTRIES_BOUNDS")
		}
		node, name, protocol, code := parseLink(line)
		receipt.Entries = append(receipt.Entries, i.entry(len(receipt.Entries)+1, digest([]byte(line)), node, name, protocol, code))
	}
	return boundedReceipt(receipt)
}

func boundedReceipt(receipt Receipt) Receipt {
	for _, entry := range receipt.Entries {
		if entry.Code == "ENTRY_NODE_BOUNDS" {
			receipt.Category = "failure"
			receipt.Code = "CONTENT_NODE_BOUNDS"
			receipt.Entries = []Entry{}
			return receipt
		}
	}
	receipt.Category = "inspected"
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaxOutputBytes {
		receipt.Category = "failure"
		receipt.Code = "CONTENT_OUTPUT_BOUNDS"
		receipt.Entries = []Entry{}
	}
	return receipt
}

func (i *Inspector) entry(position int, entryDigest string, node map[string]any, name, protocol, code string) Entry {
	entry := Entry{Position: position, Protocol: protocol, Status: "invalid", Code: code, EntryDigest: entryDigest}
	if !protocolPattern.MatchString(protocol) {
		entry.Protocol = "unknown"
		if code == "" {
			code = "ENTRY_PROTOCOL_INVALID"
		}
	}
	entry.DisplayName = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	if len(entry.DisplayName) > 512 {
		entry.DisplayName = ""
		code = "ENTRY_NAME_BOUNDS"
	}
	var encoded []byte
	if code == "" {
		var err error
		encoded, err = json.Marshal(node)
		if err != nil || len(encoded) > MaxInputBytes {
			code = "ENTRY_NODE_BOUNDS"
		}
	}
	if code == "" {
		if err := config.ValidateMobileNode(node, i.networkObserver); err != nil {
			var detail *config.MobileValidationError
			code = "ENTRY_CONSTRUCTION_INVALID"
			if errors.As(err, &detail) && detail.Code == "CAPABILITY_NOT_COVERED" {
				code = "ENTRY_CAPABILITY_UNSUPPORTED"
			}
			if detail != nil && detail.Code == "PROXY_TYPE_UNSUPPORTED" {
				code = "ENTRY_PROTOCOL_UNSUPPORTED"
			}
			if detail != nil && strings.HasSuffix(detail.Code, "NOT_IMPLEMENTED") {
				code = "ENTRY_INTEGRATION_NOT_IMPLEMENTED"
			}
		}
	}
	entry.Code = code
	if code != "" {
		if strings.Contains(code, "UNSUPPORTED") || strings.HasSuffix(code, "NOT_IMPLEMENTED") {
			entry.Status = "unsupported"
		}
		return entry
	}
	entry.Status = "supported"
	entry.NodeJSON = string(encoded)
	entry.CanonicalDigest = digest(encoded)
	return entry
}
