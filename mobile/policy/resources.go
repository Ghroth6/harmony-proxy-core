package policy

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	"go.yaml.in/yaml/v3"
)

type fixedResource struct {
	value contract.Resource
	bytes []byte
}

func (e *Engine) loadResources(available []contract.Resource) (map[string]fixedResource, string) {
	result := map[string]fixedResource{}
	var total int64
	for _, resource := range available {
		if !contract.IsDigest(resource.RefID) || !contract.IsDigest(resource.SourceDigest) || !contract.IsDigest(resource.ContentDigest) || resource.ByteLength <= 0 || resource.ByteLength > contract.MaxBinaryBytes || result[resource.RefID].value.RefID != "" {
			return nil, "POLICY_RESOURCE_IDENTITY_INVALID"
		}
		allowed := resource.Kind == "rule-provider" && (resource.Format == "yaml" || resource.Format == "text" || resource.Format == "mrs") || (resource.Kind == "mmdb" || resource.Kind == "asn") && resource.Format == "mmdb" || (resource.Kind == "geoip" || resource.Kind == "geosite") && resource.Format == "dat"
		if !allowed {
			return nil, "POLICY_RESOURCE_IDENTITY_INVALID"
		}
		if resource.Kind == "rule-provider" && resource.ByteLength > contract.MaxTextBytes && resource.Format != "mrs" {
			return nil, "POLICY_RESOURCE_BOUNDS"
		}
		total += resource.ByteLength
		if total > contract.MaxTotalBytes {
			return nil, "POLICY_RESOURCE_BOUNDS"
		}
		expected := "immutable/" + resource.ContentDigest[7:] + "/" + resource.Kind + "." + resource.Format
		if resource.RelativePath != expected {
			return nil, "POLICY_RESOURCE_PATH_INVALID"
		}
		result[resource.RefID] = fixedResource{value: resource}
	}
	for _, resource := range available {
		// os.Root protects traversal; reject even an in-root symlink/reparse
		// component so an immutable resource cannot be silently redirected.
		segments := strings.Split(resource.RelativePath, "/")
		for index := range segments {
			info, err := e.root.Lstat(path.Join(segments[:index+1]...))
			if err != nil {
				return nil, "POLICY_RESOURCE_READ_FAILED"
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, "POLICY_RESOURCE_PATH_INVALID"
			}
			if index < len(segments)-1 && !info.IsDir() {
				return nil, "POLICY_RESOURCE_PATH_INVALID"
			}
		}
		file, err := e.root.Open(resource.RelativePath)
		if err != nil {
			return nil, "POLICY_RESOURCE_READ_FAILED"
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			e.retainClose(file, file.Close())
			return nil, "POLICY_RESOURCE_PATH_INVALID"
		}
		data, readErr := io.ReadAll(io.LimitReader(file, resource.ByteLength+1))
		closeErr := file.Close()
		e.retainClose(file, closeErr)
		if readErr != nil || closeErr != nil {
			return nil, "POLICY_RESOURCE_READ_FAILED"
		}
		if info.Size() != resource.ByteLength || int64(len(data)) != resource.ByteLength || contract.Digest(data) != resource.ContentDigest {
			return nil, "POLICY_RESOURCE_DIGEST_INVALID"
		}
		result[resource.RefID] = fixedResource{value: resource, bytes: data}
	}
	return result, ""
}

func matchResource(requirement contract.Requirement, resource fixedResource) string {
	value := resource.value
	if value.RefID != requirement.RefID || value.Kind != requirement.Kind || value.Format != requirement.Format || value.SourceDigest != requirement.SourceDigest {
		return "POLICY_RESOURCE_IDENTITY_INVALID"
	}
	if value.ByteLength > requirement.MaxBytes {
		return "POLICY_RESOURCE_BOUNDS"
	}
	return ""
}

func providerPayload(data []byte, format, behavior string) ([]string, string) {
	if !utf8.Valid(data) || len(data) > contract.MaxTextBytes {
		return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
	}
	var payload []string
	switch format {
	case "yaml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var document, extra yaml.Node
		if decoder.Decode(&document) != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || strictYAML(document.Content[0], 0) != nil || decoder.Decode(&extra) != io.EOF {
			return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
		}
		var value struct {
			Payload []string `yaml:"payload"`
		}
		decoder = yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if decoder.Decode(&value) != nil || value.Payload == nil {
			return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
		}
		payload = value.Payload
	case "text":
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			payload = append(payload, line)
		}
	default:
		return nil, "POLICY_RESOURCE_FORMAT_UNSUPPORTED"
	}
	if len(payload) > 262144 {
		return nil, "POLICY_RESOURCE_BOUNDS"
	}
	for _, line := range payload {
		if strings.TrimSpace(line) == "" {
			return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
		}
		switch behavior {
		case "classical":
			tp, value, target, params := RC.ParseRulePayload(line, false)
			if _, err := preflightProviderRule(tp, value, target, params, nil); err != nil {
				return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
			}
		case "domain":
			if !domainPayload.MatchString(line) {
				return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
			}
		case "ipcidr":
			if _, err := netip.ParsePrefix(line); err != nil {
				return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
			}
		default:
			return nil, "POLICY_RESOURCE_BEHAVIOR_UNSUPPORTED"
		}
	}
	return payload, ""
}

var domainPayload = regexp.MustCompile(`^(?:\+\.|\*\.|\.)?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?$`)
var geoPayload = regexp.MustCompile(`^!?[A-Za-z0-9_-]+(?:@[A-Za-z0-9_-]+)?$`)

// Planning can validate a geodata reference's syntax and discover its bytes,
// but only the later resource-scoped constructor may compile that matcher.
func preflightProviderRule(tp, payload, target string, params []string, sub map[string][]C.Rule) (C.Rule, error) {
	switch tp {
	case "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN":
		if !geoPayload.MatchString(payload) {
			return nil, errors.New("geodata reference")
		}
		for _, param := range params {
			if param != "src" && param != "no-resolve" {
				return nil, errors.New("geodata parameter")
			}
		}
		return RC.NewMatch(target), nil
	case "AND":
		return logic.NewAND(payload, target, preflightProviderRule)
	case "OR":
		return logic.NewOR(payload, target, preflightProviderRule)
	case "NOT":
		return logic.NewNOT(payload, target, preflightProviderRule)
	case "MATCH", "SUB-RULE", "RULE-SET":
		return nil, errors.New("provider nested rule not yet validated")
	default:
		return rules.ParseRule(tp, payload, target, params, sub)
	}
}
