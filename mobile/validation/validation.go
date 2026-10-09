// Package validation exposes the single read-only mobile validation operation.
// It only constructs and discards the explicitly gated static subset, never
// applying a configuration or calling the full resource-constructing parser.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/metacubex/mihomo/config"
)

const (
	MaxInputBytes     = 1024 * 1024
	MaxOperationBytes = 128
	ABIVersion        = 1
)

// SourceRevision is set by the build to the immutable source commit. Unstamped
// development builds identify themselves explicitly and cannot prove provenance.
var SourceRevision = "development-unidentified"

type Diagnostic struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

type CoreIdentity struct {
	Name             string `json:"name"`
	SourceRevision   string `json:"sourceRevision"`
	UpstreamRevision string `json:"upstreamRevision"`
	ABIVersion       int    `json:"abiVersion"`
}

type Receipt struct {
	SchemaVersion int          `json:"schemaVersion"`
	OperationID   string       `json:"operationId"`
	InputDigest   string       `json:"inputDigest"`
	Phase         string       `json:"phase"`
	Category      string       `json:"category"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
	CoreIdentity  CoreIdentity `json:"coreIdentity"`
	Covered       []string     `json:"covered"`
	Uncovered     []string     `json:"uncovered"`
}

func Validate(operationID string, input []byte) (receipt Receipt) {
	digest := sha256.Sum256(input)
	receipt = Receipt{
		SchemaVersion: 1, OperationID: operationID,
		InputDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Phase:       "format", Category: "failure",
		Diagnostics: []Diagnostic{}, Covered: []string{},
		Uncovered: []string{"semantic-validation"},
		CoreIdentity: CoreIdentity{Name: "Mihomo", SourceRevision: SourceRevision,
			UpstreamRevision: "88dcbf7f1614a67c3b36b848ee3592dfa92ada36", ABIVersion: ABIVersion},
	}
	defer func() {
		if recover() != nil {
			receipt.Category = "failure"
			receipt.Diagnostics = []Diagnostic{{Code: "CORE_FAILURE", Field: "", Message: "Core validation did not complete."}}
		}
	}()
	if len(operationID) == 0 || len(operationID) > MaxOperationBytes || len(input) > MaxInputBytes {
		receipt.Diagnostics = []Diagnostic{{Code: "REQUEST_BOUNDS", Field: "", Message: "Validation request exceeds the operation or input limit."}}
		return
	}
	if strings.TrimSpace(string(input)) == "" {
		receipt.Category = "invalid"
		receipt.Diagnostics = []Diagnostic{{Code: "CONFIG_EMPTY", Field: "", Message: "Configuration is empty."}}
		return
	}
	raw, err := config.UnmarshalRawConfig(input)
	if err != nil {
		receipt.Category = "invalid"
		// Core errors can echo scalar values (including credentials). Preserve
		// the classification, never publish the unsanitized parser error.
		receipt.Diagnostics = []Diagnostic{{Code: "FORMAT_INVALID", Field: "", Message: "Mihomo could not decode the configuration format."}}
		return
	}
	receipt.Covered = []string{"mihomo-format"}
	receipt.Phase = "semantic"
	if diagnostics := inspectInputScope(input); len(diagnostics) != 0 {
		receipt.Category = "incomplete"
		receipt.Diagnostics = diagnostics
		for _, diagnostic := range diagnostics {
			if diagnostic.Field != "" {
				receipt.Uncovered = append(receipt.Uncovered, diagnostic.Field)
			}
		}
		return
	}
	if err := config.ValidateMobileStatic(raw); err != nil {
		receipt.Category = "invalid"
		var diagnostic *config.MobileValidationError
		if errors.As(err, &diagnostic) {
			if diagnostic.Code == "CANDIDATE_CLEANUP_FAILED" {
				receipt.Category = "failure"
			} else if diagnostic.Code == "CAPABILITY_NOT_COVERED" {
				receipt.Category = "incomplete"
			}
			message := "Mihomo rejected a static node or proxy group definition."
			switch diagnostic.Code {
			case "GROUP_REFERENCE_INVALID":
				message = "A select group references a proxy node or group that does not exist."
			case "RULE_REFERENCE_INVALID":
				message = "A static rule references a proxy node or group that does not exist."
			case "RULE_INVALID":
				message = "A static rule has an invalid definition."
			case "CAPABILITY_NOT_COVERED":
				message = "This field or capability is outside the current static validation scope."
			case "CANDIDATE_CLEANUP_FAILED":
				message = "Temporary validation objects could not be completely released."
			}
			receipt.Diagnostics = []Diagnostic{{Code: diagnostic.Code, Field: diagnostic.Field, Message: message}}
		} else {
			receipt.Category = "failure"
			receipt.Diagnostics = []Diagnostic{{Code: "CORE_FAILURE", Field: "", Message: "Core validation did not complete."}}
		}
		return
	}
	receipt.Category = "pass"
	transport := "static-ss-aes-128-gcm"
	if len(raw.Proxy) == 1 && raw.Proxy[0]["type"] == "trojan" {
		transport = "static-trojan-tcp-tls-sni"
	}
	receipt.Covered = append(receipt.Covered, transport, "explicit-select-references", "DOMAIN-MATCH-rule-references", "candidate-resources-closed")
	if fixedRuntimeScope(raw) {
		receipt.Covered = append(receipt.Covered, "m1b-fixed-ipv4-tcp")
	}
	receipt.Uncovered = []string{"runtime-connectivity", "other-protocols-fields-and-rule-types"}
	return
}
