package content

import (
	"bytes"
	"encoding/json"
	"io"

	"go.yaml.in/yaml/v3"
)

func yamlValue(node *yaml.Node, depth int) (any, string) {
	if node == nil || depth > 32 {
		return nil, "ENTRY_STRUCTURE_INVALID"
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
		return nil, "ENTRY_ALIAS_UNSUPPORTED"
	}
	switch node.Kind {
	case yaml.MappingNode:
		result := make(map[string]any)
		for n := 0; n < len(node.Content); n += 2 {
			key := node.Content[n]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return nil, "ENTRY_STRUCTURE_INVALID"
			}
			if key.Value == "<<" {
				return nil, "ENTRY_ALIAS_UNSUPPORTED"
			}
			if _, duplicate := result[key.Value]; duplicate {
				return nil, "ENTRY_PARAMETER_DUPLICATE"
			}
			value, code := yamlValue(node.Content[n+1], depth+1)
			if code != "" {
				return nil, code
			}
			result[key.Value] = value
		}
		return result, ""
	case yaml.SequenceNode:
		result := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, code := yamlValue(child, depth+1)
			if code != "" {
				return nil, code
			}
			result = append(result, value)
		}
		return result, ""
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!bool", "!!int", "!!float":
		default:
			return nil, "ENTRY_STRUCTURE_INVALID"
		}
		var result any
		if node.Decode(&result) != nil {
			return nil, "ENTRY_STRUCTURE_INVALID"
		}
		return result, ""
	default:
		return nil, "ENTRY_STRUCTURE_INVALID"
	}
}

func (i *Inspector) inspectYAML(input []byte) ([]Entry, string) {
	d := yaml.NewDecoder(bytes.NewReader(input))
	var document yaml.Node
	if d.Decode(&document) != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, "CONTENT_FORMAT_INVALID"
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return nil, "CONTENT_DOCUMENTS_INVALID"
	}
	root := document.Content[0]
	seen := make(map[string]bool)
	var proxies *yaml.Node
	for n := 0; n < len(root.Content); n += 2 {
		key := root.Content[n]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
			return nil, "CONTENT_MAPPING_INVALID"
		}
		seen[key.Value] = true
		if key.Value == "proxies" {
			proxies = root.Content[n+1]
		}
	}
	if proxies == nil {
		return []Entry{}, ""
	} // Original policy may contain only prepared provider references.
	if proxies.Kind != yaml.SequenceNode {
		return nil, "CONTENT_PROXIES_INVALID"
	}
	if len(proxies.Content) > MaxEntries {
		return nil, "CONTENT_ENTRIES_BOUNDS"
	}
	entries := make([]Entry, 0, len(proxies.Content))
	for _, original := range proxies.Content {
		value, code := yamlValue(original, 0)
		encoded, _ := json.Marshal(value)
		if code != "" {
			encoded, _ = json.Marshal(original)
		}
		if len(encoded) > MaxInputBytes {
			return nil, "CONTENT_NODE_BOUNDS"
		}
		node, ok := value.(map[string]any)
		if code == "" && !ok {
			code = "ENTRY_STRUCTURE_INVALID"
		}
		name, _ := node["name"].(string)
		protocol, _ := node["type"].(string)
		if code == "" {
			node["name"] = "selected-node"
		}
		entries = append(entries, i.entry(len(entries)+1, digest(encoded), node, name, protocol, code))
	}
	return entries, ""
}
