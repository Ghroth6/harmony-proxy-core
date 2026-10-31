package validation_test

import (
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/validation"
	"reflect"
	"testing"
)

func TestFormatUsesOfficialDecoderWithoutSubsetPolicy(t *testing.T) {
	for _, input := range []string{
		"mode: rule\ndns:\n  enable: true\n",
		"notes: &note [one, two]\nother: *note\n",
		"proxy-providers:\n  source:\n    type: http\n    url: http://127.0.0.1:1/never-requested\n",
		"proxies: [{type: not-yet-known, name: untouched}]\n",
		"proxies: [\n",
	} {
		_, err := config.UnmarshalRawConfig([]byte(input))
		got := validation.Validate("official-format", []byte(input))
		if err != nil {
			if got.Category != "invalid" {
				t.Fatalf("official rejection differs: %+v", got)
			}
		} else if got.Category != "incomplete" || got.Phase != "format" || !reflect.DeepEqual(got.Covered, []string{"mihomo-format"}) || !reflect.DeepEqual(got.Uncovered, []string{"semantic-validation"}) {
			t.Fatalf("format must not claim runtime or semantic support: %+v", got)
		}
	}
}
