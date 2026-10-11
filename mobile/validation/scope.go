package validation

import (
	"bytes"
	"errors"
	"github.com/metacubex/mihomo/config"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// inspectInputScope examines original bytes rather than Mihomo's typed result,
// which deliberately ignores unrecognized YAML keys. No resource constructors
// or resource lookup are called here.
func inspectInputScope(input []byte, extendedSelected bool) []Diagnostic {
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var document yaml.Node
	if decoder.Decode(&document) != nil {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", "", "The original document could not be inspected within this validation scope.")
	}
	var additional yaml.Node
	if err := decoder.Decode(&additional); err != io.EOF {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", "", "Multiple YAML documents are outside this validation scope.")
	}
	return inspectScope(&document, extendedSelected)
}

func inspectScope(document *yaml.Node, extendedSelected bool) []Diagnostic {
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", "", "A single configuration mapping is required for this validation scope.")
	}
	root := document.Content[0]
	if !recognizedYAMLTag(root.Tag) {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", "", "Custom YAML tags have not been checked.")
	}
	for index := 0; index < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		field := safeField("", key.Value, index/2)
		if !recognizedYAMLTag(key.Tag) {
			return scopeDiagnostic("UNSUPPORTED_DOCUMENT", field, "Custom YAML tags have not been checked.")
		}
		if unsupported := inspectYAML(value, field, make(map[*yaml.Node]bool), 0); unsupported != nil {
			return unsupported
		}
		if key.Kind != yaml.ScalarNode || key.Value == "<<" || key.Tag == "!!merge" {
			return scopeDiagnostic("YAML_ALIAS_UNCHECKED", field, "YAML aliases and merge keys have not been checked.")
		}
		switch key.Value {
		case "proxy-providers", "rule-providers":
			return resourceDiagnostic(value, field)
		case "geox-url", "external-ui", "external-ui-url":
			return scopeDiagnostic("RESOURCE_UNAVAILABLE", field, "Referenced configuration resources have not been prepared for validation.")
		case "proxies":
			if extendedSelected && value.Kind == yaml.SequenceNode {
				for _, entry := range value.Content {
					var node map[string]any
					if entry.Decode(&node) != nil {
						continue
					}
					var diagnostic *config.MobileValidationError
					if err := config.MobileNodeFields(node); errors.As(err, &diagnostic) && diagnostic.Code == "CAPABILITY_NOT_COVERED" {
						return scopeDiagnostic("UNSUPPORTED_CAPABILITY", field, "An original node field or value has not been covered.")
					}
				}
				continue
			}
			if result := inspectEntries(value, field, true); result != nil {
				return result
			}
		case "proxy-groups":
			if result := inspectEntries(value, field, false); result != nil {
				return result
			}
		case "rules":
			if value.Kind != yaml.SequenceNode {
				continue
			} // Actual type errors belong to Mihomo.
			for itemIndex, item := range value.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				ruleParts := strings.Split(item.Value, ",")
				ruleType := ruleParts[0]
				location := field + "/" + strconv.Itoa(itemIndex)
				if (ruleType == "DOMAIN" && len(ruleParts) > 3) || (ruleType == "MATCH" && len(ruleParts) > 2) {
					return scopeDiagnostic("UNSUPPORTED_CAPABILITY", location, "Extra rule parameters have not been checked.")
				}
				switch ruleType {
				case "DOMAIN", "MATCH":
				case "RULE-SET", "GEOIP", "GEOSITE", "IP-ASN":
					return scopeDiagnostic("RESOURCE_UNAVAILABLE", location, "Referenced rule resources have not been prepared for validation.")
				default:
					return scopeDiagnostic("UNSUPPORTED_CAPABILITY", location, "This rule capability has not been checked.")
				}
			}
		default:
			return scopeDiagnostic("UNSUPPORTED_FIELD", field, "This configuration field has not been checked.")
		}
	}
	return nil
}

func inspectEntries(sequence *yaml.Node, field string, proxy bool) []Diagnostic {
	if sequence.Kind != yaml.SequenceNode {
		return nil
	}
	for index, entry := range sequence.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		location := field + "/" + strconv.Itoa(index)
		// Select the whitelist before walking fields: YAML field order cannot
		// grant SS the Trojan TLS options, or Trojan the SS cipher option.
		protocol := ""
		if proxy {
			for pairIndex := 0; pairIndex < len(entry.Content); pairIndex += 2 {
				if entry.Content[pairIndex].Value == "type" {
					protocol = entry.Content[pairIndex+1].Value
				}
			}
		}
		for pairIndex := 0; pairIndex < len(entry.Content); pairIndex += 2 {
			key, value := entry.Content[pairIndex], entry.Content[pairIndex+1]
			child := safeField(location, key.Value, pairIndex/2)
			allowed := key.Value == "name" || key.Value == "type" || (!proxy && key.Value == "proxies") ||
				(proxy && (key.Value == "server" || key.Value == "port" || key.Value == "password" || key.Value == "udp" ||
					(protocol == "ss" && key.Value == "cipher") ||
					(protocol == "trojan" && (key.Value == "sni" || key.Value == "network" || key.Value == "skip-cert-verify"))))
			if key.Value == "use" || key.Value == "url" || key.Value == "path" {
				return scopeDiagnostic("RESOURCE_UNAVAILABLE", child, "Referenced configuration resources have not been prepared for validation.")
			}
			if !allowed {
				return scopeDiagnostic("UNSUPPORTED_FIELD", child, "This node or group field has not been checked.")
			}
			if key.Value == "type" && value.Kind == yaml.ScalarNode && ((proxy && value.Value != "ss" && value.Value != "trojan") || (!proxy && value.Value != "select")) {
				return scopeDiagnostic("UNSUPPORTED_CAPABILITY", child, "This node or group capability has not been checked.")
			}
			if proxy && key.Value == "cipher" && value.Kind == yaml.ScalarNode && value.Value != "aes-128-gcm" && value.Value != "chacha20-ietf-poly1305" {
				return scopeDiagnostic("UNSUPPORTED_CAPABILITY", child, "This encryption capability has not been checked.")
			}
		}
	}
	return nil
}

// Aliases are conservatively incomplete, without following links. Anchor cycles
// therefore cannot recurse forever. Depth limits also keep inspection bounded.
func inspectYAML(node *yaml.Node, field string, visiting map[*yaml.Node]bool, depth int) []Diagnostic {
	if node == nil || depth > 32 || visiting[node] {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", field, "The YAML structure exceeds this validation scope.")
	}
	if node.Kind == yaml.AliasNode || node.Tag == "!!merge" {
		return scopeDiagnostic("YAML_ALIAS_UNCHECKED", field, "YAML aliases and merge keys have not been checked.")
	}
	if !recognizedYAMLTag(node.Tag) {
		return scopeDiagnostic("UNSUPPORTED_DOCUMENT", field, "Custom YAML tags have not been checked.")
	}
	visiting[node] = true
	defer delete(visiting, node)
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			location := safeField(field, key.Value, index/2)
			if !recognizedYAMLTag(key.Tag) {
				return scopeDiagnostic("UNSUPPORTED_DOCUMENT", location, "Custom YAML tags have not been checked.")
			}
			if key.Kind != yaml.ScalarNode || key.Value == "<<" || key.Tag == "!!merge" {
				return scopeDiagnostic("YAML_ALIAS_UNCHECKED", location, "YAML aliases and merge keys have not been checked.")
			}
			if result := inspectYAML(node.Content[index+1], location, visiting, depth+1); result != nil {
				return result
			}
		}
	} else {
		for index, child := range node.Content {
			if result := inspectYAML(child, field+"/"+strconv.Itoa(index), visiting, depth+1); result != nil {
				return result
			}
		}
	}
	return nil
}

func resourceDiagnostic(node *yaml.Node, field string) []Diagnostic {
	if node.Kind == yaml.MappingNode {
		for entryIndex := 0; entryIndex < len(node.Content); entryIndex += 2 {
			entry := node.Content[entryIndex+1]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			for _, sought := range []string{"url", "path"} {
				for pairIndex := 0; pairIndex < len(entry.Content); pairIndex += 2 {
					if entry.Content[pairIndex].Value == sought {
						field += "/" + strconv.Itoa(entryIndex/2) + "/" + sought
						return scopeDiagnostic("RESOURCE_UNAVAILABLE", field, "Referenced configuration resources have not been prepared for validation.")
					}
				}
			}
		}
	}
	return scopeDiagnostic("UNSUPPORTED_CAPABILITY", field, "Provider configuration without an explicit prepared reference has not been checked.")
}

// Known field names are constants. Arbitrary keys and provider names can contain
// secrets, so positional mapping indices locate them without echoing their text.
func safeField(parent, key string, index int) string {
	switch key {
	case "proxies", "proxy-groups", "rules", "proxy-providers", "rule-providers", "name", "type", "server", "port", "cipher", "password", "udp", "sni", "network", "skip-cert-verify", "url", "path", "use", "dns", "mode", "geox-url", "geodata-loader", "geodata-mode", "external-ui", "external-ui-url":
		return parent + "/" + key
	default:
		return parent + "/" + strconv.Itoa(index)
	}
}

func scopeDiagnostic(code, field, message string) []Diagnostic {
	return []Diagnostic{{Code: code, Field: field, Message: message}}
}

// yaml.v3 normalizes unknown YAML-namespace tags to !!name too. A prefix is
// therefore not proof that a tag is built-in. These are its recognized tags;
// merge remains separately incomplete in the alias/merge guards above.
func recognizedYAMLTag(tag string) bool {
	switch tag {
	case "", "!!null", "!!bool", "!!str", "!!int", "!!float", "!!timestamp", "!!seq", "!!map", "!!binary", "!!merge":
		return true
	default:
		return false
	}
}
