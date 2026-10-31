package policy

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
)

type fixedResource struct {
	value contract.Resource
	bytes []byte
}

func (e *Engine) loadResources(available []contract.Resource) (map[string]fixedResource, string) {
	result := map[string]fixedResource{}
	for _, resource := range available {
		if !contract.IsDigest(resource.RefID) || !contract.IsDigest(resource.SourceDigest) || !contract.IsDigest(resource.ContentDigest) || resource.ByteLength < 0 || resource.ByteLength > contract.MaxResourceBytes || result[resource.RefID].value.RefID != "" {
			return nil, "POLICY_RESOURCE_IDENTITY_INVALID"
		}
		allowed := resource.Kind == "rule-provider" && (resource.Format == "yaml" || resource.Format == "text" || resource.Format == "mrs") || (resource.Kind == "mmdb" || resource.Kind == "asn") && resource.Format == "mmdb" || (resource.Kind == "geoip" || resource.Kind == "geosite") && resource.Format == "dat"
		if !allowed {
			return nil, "POLICY_RESOURCE_IDENTITY_INVALID"
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
	kind, err := P.ParseBehavior(behavior)
	if err != nil {
		return nil, "POLICY_RESOURCE_BEHAVIOR_UNSUPPORTED"
	}
	encoding, err := P.ParseRuleFormat(format)
	if err != nil {
		return nil, "POLICY_RESOURCE_FORMAT_UNSUPPORTED"
	}
	payload, err := RP.RuleSetPayload(data, kind, encoding, preflightProviderRule)
	if err != nil {
		return nil, "POLICY_RESOURCE_PAYLOAD_INVALID"
	}
	return payload, ""
}

// Planning can validate a geodata reference's syntax and discover its bytes,
// but only the later resource-scoped constructor may compile that matcher.
func preflightProviderRule(tp, payload, target string, params []string, sub map[string][]C.Rule) (C.Rule, error) {
	switch tp {
	case "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN":
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
