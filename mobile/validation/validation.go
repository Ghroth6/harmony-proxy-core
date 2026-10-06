// Package validation exposes the single read-only mobile validation operation.
// It never applies a configuration or calls the resource-constructing parser.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
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
	if _, err := config.UnmarshalRawConfig(input); err != nil {
		receipt.Category = "invalid"
		// Core errors can echo scalar values (including credentials). Preserve
		// the classification, never publish the unsanitized parser error.
		receipt.Diagnostics = []Diagnostic{{Code: "FORMAT_INVALID", Field: "", Message: "Mihomo could not decode the configuration format."}}
		return
	}
	receipt.Category = "incomplete"
	receipt.Covered = []string{"mihomo-format"}
	if diagnostics := inspectInputScope(input); len(diagnostics) != 0 {
		receipt.Phase = "semantic"
		receipt.Diagnostics = diagnostics
		for _, diagnostic := range diagnostics {
			if diagnostic.Field != "" {
				receipt.Uncovered = append(receipt.Uncovered, diagnostic.Field)
			}
		}
		return
	}
	receipt.Diagnostics = []Diagnostic{{Code: "SEMANTICS_NOT_CHECKED", Field: "", Message: "Format check completed; semantics have not been checked."}}
	return
}
