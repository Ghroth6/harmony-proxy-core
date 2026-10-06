package validation_test

import (
	"testing"

	"github.com/metacubex/mihomo/mobile/validation"
)

// This is diagnostic descent at the real backend operation. The acceptance
// seam is the application's validate operation and still requires OHOS runs.
func TestUnsupportedFieldIsIncompleteAndIdentifiesActualBytes(t *testing.T) {
	result := validation.Validate("format-1", []byte("mode: rule\n"))
	if result.Category != "incomplete" || result.Phase != "semantic" {
		t.Fatalf("unsupported field must remain incomplete after format decoding: %#v", result)
	}
	if result.OperationID != "format-1" || result.InputDigest != "sha256:82e9ee202366d68830de7efc4e366443a3f1b99d833584090f591620b2dfd72e" {
		t.Fatalf("receipt must identify operation and actual bytes: %#v", result)
	}
}
