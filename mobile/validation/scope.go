package validation

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

func inspectInputScope(input []byte) []Diagnostic {
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return []Diagnostic{{Code: "CAPABILITY_NOT_COVERED", Message: "The original YAML document could not be inspected safely."}}
	}
	var next yaml.Node
	if err := decoder.Decode(&next); err != io.EOF {
		return []Diagnostic{{Code: "UNSUPPORTED_DOCUMENT", Message: "Only one YAML configuration document is currently covered."}}
	}
	return inspectScope(&document)
}

// inspectScope reads the original syntax tree before any semantic constructor.
// An unsupported or ambiguous node never reaches the engine constructors.
func inspectScope(document *yaml.Node) []Diagnostic {
	unsupported := func(field string) []Diagnostic {
		return []Diagnostic{{Code: "CAPABILITY_NOT_COVERED", Field: field, Message: "This field or capability is outside the current static validation scope."}}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return unsupported("")
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return unsupported("")
	}
	var safeSyntax func(*yaml.Node) bool
	safeSyntax = func(node *yaml.Node) bool {
		switch node.Kind {
		case yaml.MappingNode:
			if node.Tag != "!!map" {
				return false
			}
		case yaml.SequenceNode:
			if node.Tag != "!!seq" {
				return false
			}
		case yaml.ScalarNode:
			if node.Tag != "!!str" && node.Tag != "!!int" && node.Tag != "!!bool" && node.Tag != "!!float" {
				return false
			}
		default:
			return false
		}
		for _, child := range node.Content {
			if !safeSyntax(child) {
				return false
			}
		}
		return true
	}
	if !safeSyntax(root) {
		return unsupported("")
	}
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return unsupported("")
		}
		field := key.Value
		if field != "proxies" && field != "proxy-groups" && field != "rules" {
			return unsupported(field)
		}
		if value.Kind != yaml.SequenceNode {
			return unsupported(field)
		}
		for index, item := range value.Content {
			path := fmt.Sprintf("%s[%d]", field, index)
			if field == "rules" {
				if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
					return unsupported(path)
				}
				kind := strings.TrimSpace(strings.SplitN(item.Value, ",", 2)[0])
				if kind != "DOMAIN" && kind != "MATCH" {
					return unsupported(path)
				}
				parts := strings.Split(item.Value, ",")
				if (kind == "DOMAIN" && len(parts) > 3) || (kind == "MATCH" && len(parts) > 2) {
					return unsupported(path)
				}
				continue
			}
			if item.Kind != yaml.MappingNode {
				return unsupported(path)
			}
			for j := 0; j < len(item.Content); j += 2 {
				name, setting := item.Content[j], item.Content[j+1]
				if name.Kind != yaml.ScalarNode || name.Tag != "!!str" {
					return unsupported(path)
				}
				allowed := name.Value == "name" || name.Value == "type"
				if field == "proxies" {
					allowed = allowed || name.Value == "server" || name.Value == "port" || name.Value == "cipher" || name.Value == "password" || name.Value == "udp"
				} else {
					allowed = allowed || name.Value == "proxies"
				}
				if !allowed {
					return unsupported(path + "." + name.Value)
				}
				if field == "proxy-groups" && name.Value == "proxies" {
					if setting.Kind != yaml.SequenceNode {
						return unsupported(path + ".proxies")
					}
					for _, reference := range setting.Content {
						if reference.Kind != yaml.ScalarNode || reference.Tag != "!!str" {
							return unsupported(path + ".proxies")
						}
					}
					continue
				}
				if setting.Kind != yaml.ScalarNode {
					return unsupported(path + "." + name.Value)
				}
				if name.Value == "type" && ((field == "proxies" && setting.Value != "ss") || (field == "proxy-groups" && setting.Value != "select")) {
					return unsupported(path + ".type")
				}
				if name.Value == "cipher" && setting.Value != "aes-128-gcm" {
					return unsupported(path + ".cipher")
				}
			}
		}
	}
	return nil
}
