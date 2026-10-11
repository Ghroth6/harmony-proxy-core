package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/metacubex/mihomo/common/orderedmap"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/metacubex/mihomo/mobile/validation"
	"go.yaml.in/yaml/v3"
)

func digest(input []byte) string {
	return contract.Digest(input)
}

func canonical(input any) ([]byte, error) {
	return contract.CanonicalJSON(input)
}

func (e *Engine) Plan(operationID string, input []byte, available []PreparedResource) PlanReceipt {
	return e.plan(operationID, input, available, nil)
}

func (e *Engine) plan(operationID string, input []byte, available []PreparedResource, verified *map[string]fixedResource) (receipt PlanReceipt) {
	receipt = PlanReceipt{SchemaVersion: contract.Version, OperationID: operationID, InputDigest: digest(input), PlannerVersion: contract.PlannerVersion,
		Category: "failure", Code: "POLICY_FAILURE", Requirements: []contract.Requirement{}, Groups: []contract.Group{}, Adaptations: []contract.Adaptation{}, CoreIdentity: validation.Identity()}
	defer func() {
		if recover() != nil {
			receipt.Category = "failure"
			receipt.Code = "POLICY_FAILURE"
			receipt.ResourcesComplete = false
		}
	}()
	if !safeOperation(operationID) || len(input) > contract.MaxControlBytes || len(available) > contract.MaxResources {
		receipt.Code = "POLICY_REQUEST_BOUNDS"
		return
	}
	if !e.available() {
		receipt.Code = "POLICY_RESOURCE_OWNER_RETIRED"
		return
	}
	raw, document, code := decodePolicy(input)
	if code != "" {
		receipt.Category = "invalid"
		receipt.Code = code
		return
	}
	receipt.GeneralIPv6, receipt.DNSEnabled, receipt.DNSIPv6 = raw.IPv6, raw.DNS.Enable, raw.DNS.IPv6
	receipt.StoreSelected, receipt.StoreFakeIP = raw.Profile.StoreSelected, raw.Profile.StoreFakeIP
	// This pinned mobile owner has no geodata refresh/swap implementation.
	// Refuse the declared behavior rather than claiming ready with a dead timer.
	if raw.GeoAutoUpdate {
		receipt.Category = "unsupported"
		receipt.Code = "POLICY_GEODATA_UPDATE_UNSUPPORTED"
		return
	}
	// Planning must not promise resource readiness for a node whose original
	// fields would be dropped or defaulted by the runtime adapter. This shared
	// gate is purely static; construction and cleanup remain in Validate/Build.
	for _, node := range raw.Proxy {
		if err := config.MobileNodeFields(node); err != nil {
			receipt.Category = "invalid"
			receipt.Code = "POLICY_PROXY_INVALID"
			var diagnostic *config.MobileValidationError
			if errors.As(err, &diagnostic) {
				receipt.Code = diagnostic.Code
				if diagnostic.Code == "CAPABILITY_NOT_COVERED" {
					receipt.Category = "unsupported"
				}
			}
			return
		}
	}
	groups, code := planGroups(raw, receipt.InputDigest)
	if code != "" {
		receipt.Category = "unsupported"
		receipt.Code = code
		return
	}
	receipt.Groups = groups
	requirements, code := planRequirements(raw, document, receipt.InputDigest)
	if code != "" {
		receipt.Category = "unsupported"
		receipt.Code = code
		return
	}
	receipt.Requirements = requirements
	if len(requirements) > contract.MaxResources {
		receipt.Code = "POLICY_RESOURCE_BOUNDS"
		return
	}
	fixed, code := e.loadResources(available)
	if code != "" {
		receipt.Category = "invalid"
		receipt.Code = code
		return
	}
	if verified != nil {
		*verified = fixed
	}
	providerRules := []string{}
	for name, mapping := range raw.RuleProvider {
		behavior, _ := mapping["behavior"].(string)
		if mapping["type"] == "inline" {
			encoded, err := yaml.Marshal(map[string]any{"payload": mapping["payload"]})
			if err != nil {
				receipt.Category = "invalid"
				receipt.Code = "POLICY_RESOURCE_PAYLOAD_INVALID"
				return
			}
			if _, code = providerPayload(encoded, "yaml", behavior); code != "" {
				receipt.Category = "invalid"
				receipt.Code = code
				return
			}
			continue
		}
		ref := digest([]byte(receipt.InputDigest + ":resource:rule-provider:" + name))
		resource, present := fixed[ref]
		if !present {
			continue
		}
		for _, requirement := range requirements {
			if requirement.RefID == ref {
				if code = matchResource(requirement, resource); code != "" {
					receipt.Category = "invalid"
					receipt.Code = code
					return
				}
			}
		}
		payload, payloadCode := providerPayload(resource.bytes, resource.value.Format, behavior)
		if payloadCode != "" {
			receipt.Category = "invalid"
			receipt.Code = payloadCode
			return
		}
		if behavior == "classical" {
			providerRules = append(providerRules, payload...)
		}
	}
	if len(providerRules) != 0 {
		requirements, code = planRequirements(raw, document, receipt.InputDigest, providerRules)
		if code != "" {
			receipt.Category = "invalid"
			receipt.Code = code
			return
		}
		receipt.Requirements = requirements
	}
	receipt.ResourcesComplete = true
	known := map[string]bool{}
	for _, requirement := range requirements {
		known[requirement.RefID] = true
		resource, present := fixed[requirement.RefID]
		if !present {
			receipt.ResourcesComplete = false
			continue
		}
		if code = matchResource(requirement, resource); code != "" {
			receipt.Category = "invalid"
			receipt.Code = code
			receipt.ResourcesComplete = false
			return
		}
		if requirement.Kind != "rule-provider" && geodata.VerifyPrepared(requirement.Kind, resource.bytes) != nil {
			receipt.Category = "invalid"
			receipt.Code = "POLICY_RESOURCE_PAYLOAD_INVALID"
			receipt.ResourcesComplete = false
			return
		}
	}
	for ref := range fixed {
		if !known[ref] {
			receipt.Category = "invalid"
			receipt.Code = "POLICY_RESOURCE_IDENTITY_INVALID"
			receipt.ResourcesComplete = false
			return
		}
	}
	receipt.Adaptations = []contract.Adaptation{{Code: "PLATFORM_OWNS_TUN", Implemented: true}, {Code: "PLATFORM_OWNS_CONTROL_LISTENERS", Implemented: true}}
	if raw.Profile.Tracing != nil {
		receipt.Adaptations = append(receipt.Adaptations, contract.Adaptation{Code: "PLATFORM_OWNS_CONNECTION_OBSERVATIONS", Implemented: true})
	}
	for _, rule := range append(append([]string{}, raw.Rule...), allSubRules(raw)...) {
		if strings.Contains(rule, "PROCESS-NAME,") || strings.Contains(rule, "PROCESS-PATH,") {
			receipt.Adaptations = append(receipt.Adaptations, contract.Adaptation{Code: "PROCESS_LOOKUP_UNVERIFIED", Implemented: false})
			break
		}
	}
	receipt.Category = "planned"
	receipt.Code = ""
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > contract.MaxResultBytes {
		receipt.Category = "failure"
		receipt.Code = "POLICY_RESULT_BOUNDS"
		receipt.ResourcesComplete = false
		receipt.Groups = []contract.Group{}
		receipt.Requirements = []contract.Requirement{}
	}
	return
}

func safeOperation(value string) bool {
	if len(value) == 0 || len(value) > validation.MaxOperationBytes {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == ':') {
			return false
		}
	}
	return true
}

func decodePolicy(input []byte) (*config.RawConfig, *yaml.Node, string) {
	if !utf8.Valid(input) || len(bytes.TrimSpace(input)) == 0 {
		return nil, nil, "POLICY_FORMAT_INVALID"
	}
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var document, extra yaml.Node
	if decoder.Decode(&document) != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, nil, "POLICY_FORMAT_INVALID"
	}
	if decoder.Decode(&extra) != io.EOF {
		return nil, nil, "POLICY_DOCUMENTS_INVALID"
	}
	if err := strictYAML(document.Content[0], 0); err != nil {
		return nil, nil, "POLICY_STRUCTURE_INVALID"
	}
	raw := config.DefaultRawConfig()
	// Mobile defaults must not inherit a previously published mutable global.
	raw.GeodataMode = false
	decoder = yaml.NewDecoder(bytes.NewReader(input))
	decoder.KnownFields(true)
	if decoder.Decode(raw) != nil {
		return nil, nil, "POLICY_FORMAT_INVALID"
	}
	return raw, document.Content[0], ""
}

func strictYAML(node *yaml.Node, depth int) error {
	if depth > 32 || node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
		return errors.New("policy structure")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return errors.New("policy mapping")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := strictYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func planGroups(raw *config.RawConfig, inputDigest string) ([]contract.Group, string) {
	if len(raw.ProxyGroup) > contract.MaxGroups {
		return nil, "POLICY_GROUP_BOUNDS"
	}
	names := map[string]string{"DIRECT": "builtin", "REJECT": "builtin", "REJECT-DROP": "builtin", "PASS": "builtin", "COMPATIBLE": "builtin"}
	for _, node := range raw.Proxy {
		name, ok := node["name"].(string)
		if !ok || name == "" || names[name] != "" {
			return nil, "POLICY_GROUP_INVALID"
		}
		names[name] = "node"
	}
	for _, group := range raw.ProxyGroup {
		name, ok := group["name"].(string)
		if !ok || name == "" || names[name] != "" {
			return nil, "POLICY_GROUP_INVALID"
		}
		names[name] = "group"
	}
	groups := []contract.Group{}
	total := 0
	for position, group := range raw.ProxyGroup {
		name := group["name"].(string)
		kind, _ := group["type"].(string)
		if kind != "select" && kind != "url-test" && kind != "fallback" {
			return nil, "POLICY_GROUP_UNSUPPORTED"
		}
		if code := groupFields(group, kind); code != "" {
			return nil, code
		}
		members, ok := group["proxies"].([]any)
		if !ok {
			return nil, "POLICY_GROUP_UNSUPPORTED"
		}
		total += len(members)
		if len(members) > contract.MaxMembers || total > contract.MaxTotalMembers {
			return nil, "POLICY_GROUP_BOUNDS"
		}
		item := contract.Group{GroupRef: digest([]byte(inputDigest + ":group:" + strconv.Itoa(position+1))), Position: position + 1, DisplayName: safeName(name), Type: kind, Members: []contract.Member{}}
		for index, member := range members {
			name, ok := member.(string)
			if !ok || names[name] == "" {
				return nil, "POLICY_GROUP_INVALID"
			}
			item.Members = append(item.Members, contract.Member{MemberRef: digest([]byte(inputDigest + ":group:" + strconv.Itoa(position+1) + ":member:" + strconv.Itoa(index+1))), Position: index + 1, DisplayName: safeName(name), Kind: names[name]})
		}
		groups = append(groups, item)
	}
	return groups, ""
}

// Group maps bypass yaml.KnownFields and the upstream decoder is deliberately
// weak. Gate every declared value before that decoder can drop or coerce it.
func groupFields(group map[string]any, kind string) string {
	for key, value := range group {
		switch key {
		case "name", "type", "url", "empty-fallback", "filter", "exclude-filter", "exclude-type", "icon":
			if _, ok := value.(string); !ok {
				return "POLICY_GROUP_INVALID"
			}
		case "expected-status":
			if _, ok := value.(string); !ok {
				if status, ok := value.(int); !ok || status < 0 || status > 65535 {
					return "POLICY_GROUP_INVALID"
				}
			}
		case "default-selected":
			if kind != "select" {
				return "POLICY_GROUP_PARAMETER_UNSUPPORTED"
			}
			if _, ok := value.(string); !ok {
				return "POLICY_GROUP_INVALID"
			}
		case "tolerance":
			if kind != "url-test" {
				return "POLICY_GROUP_PARAMETER_UNSUPPORTED"
			}
			n, ok := value.(int)
			if !ok || n < 0 || n > 65535 {
				return "POLICY_GROUP_INVALID"
			}
		case "interval", "timeout", "max-failed-times":
			n, ok := value.(int)
			if !ok || n < 0 {
				return "POLICY_GROUP_INVALID"
			}
		case "lazy", "disable-udp", "hidden":
			if _, ok := value.(bool); !ok {
				return "POLICY_GROUP_INVALID"
			}
		case "proxies":
			if _, ok := value.([]any); !ok {
				return "POLICY_GROUP_INVALID"
			}
		case "use", "include-all", "include-all-proxies", "include-all-providers":
			// These alter the effective member list, which this exact opaque
			// original-member contract does not yet construct or expose.
			return "POLICY_GROUP_PARAMETER_UNSUPPORTED"
		default:
			return "POLICY_GROUP_PARAMETER_UNSUPPORTED"
		}
	}
	return ""
}

func safeName(name string) string {
	if len(name) > 512 {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
}

func allSubRules(raw *config.RawConfig) []string {
	result := []string{}
	for _, rules := range raw.SubRules {
		result = append(result, rules...)
	}
	return result
}

func planRequirements(raw *config.RawConfig, document *yaml.Node, inputDigest string, preparedRules ...[]string) ([]contract.Requirement, string) {
	if len(raw.ProxyProvider) != 0 {
		return nil, "POLICY_PROXY_PROVIDER_UNSUPPORTED"
	}
	result := []contract.Requirement{}
	add := func(kind, format, logical, sourceKind, uri, headers, path, proxy string, interval, maxBytes int64) {
		description := map[string]any{"kind": kind, "format": format, "sourceKind": sourceKind, "sourceUri": uri, "sourceHeadersJson": headers, "originalPath": path, "downloadProxy": proxy, "intervalSeconds": interval, "maxBytes": maxBytes}
		encoded, _ := canonical(description)
		result = append(result, contract.Requirement{RefID: digest([]byte(inputDigest + ":resource:" + kind + ":" + logical)), Kind: kind, Format: format, SourceKind: sourceKind, SourceDigest: digest(encoded), SourceURI: uri, SourceHeadersJSON: headers, OriginalPath: path, DownloadProxy: proxy, IntervalSeconds: interval, MaxBytes: maxBytes})
	}
	logicalNames := make([]string, 0, len(raw.RuleProvider))
	for name := range raw.RuleProvider {
		logicalNames = append(logicalNames, name)
	}
	sort.Strings(logicalNames)
	for _, name := range logicalNames {
		value := raw.RuleProvider[name]
		for key := range value {
			if !strings.Contains(" type behavior path url proxy format interval size-limit payload header path-in-bundle ", " "+key+" ") {
				return nil, "POLICY_RESOURCE_FIELD_UNSUPPORTED"
			}
		}
		kind, _ := value["type"].(string)
		behavior, _ := value["behavior"].(string)
		format, _ := value["format"].(string)
		if format == "" {
			format = "yaml"
		}
		if behavior != "classical" && behavior != "domain" && behavior != "ipcidr" {
			return nil, "POLICY_RESOURCE_BEHAVIOR_UNSUPPORTED"
		}
		if format != "yaml" && format != "text" {
			return nil, "POLICY_RESOURCE_FORMAT_UNSUPPORTED"
		}
		if kind == "inline" {
			continue
		}
		if kind != "http" && kind != "file" {
			return nil, "POLICY_RESOURCE_SOURCE_UNSUPPORTED"
		}
		uri, _ := value["url"].(string)
		path, _ := value["path"].(string)
		proxy, _ := value["proxy"].(string)
		if kind == "http" {
			u, err := url.Parse(uri)
			if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
				return nil, "POLICY_RESOURCE_SOURCE_INVALID"
			}
		} else if path == "" {
			return nil, "POLICY_RESOURCE_SOURCE_INVALID"
		}
		interval := int64(0)
		if item, present := value["interval"]; present {
			number, ok := item.(int)
			if !ok || number < 0 {
				return nil, "POLICY_RESOURCE_INTERVAL_INVALID"
			}
			interval = int64(number)
		}
		headers := ""
		if value, ok := value["header"]; ok {
			encoded, err := canonical(value)
			if err != nil {
				return nil, "POLICY_RESOURCE_HEADERS_INVALID"
			}
			headers = string(encoded)
		}
		maxBytes := int64(contract.MaxTextBytes)
		if limit, present := value["size-limit"]; present {
			number, ok := limit.(int)
			if !ok || number < 0 {
				return nil, "POLICY_RESOURCE_BOUNDS"
			}
			if number > 0 && int64(number) < maxBytes {
				maxBytes = int64(number)
			}
		}
		add("rule-provider", format, name, kind, uri, headers, path, proxy, interval, maxBytes)
	}
	flags := map[string]bool{}
	scanRule := func(text string) {
		upper := strings.ToUpper(text)
		if regexp.MustCompile(`(?:^|\()(?:SRC-)?GEOIP,`).MatchString(upper) {
			if raw.GeodataMode {
				flags["geoip"] = true
			} else {
				flags["mmdb"] = true
			}
		}
		if regexp.MustCompile(`(?:^|\()GEOSITE,`).MatchString(upper) {
			flags["geosite"] = true
		}
		if regexp.MustCompile(`(?:^|\()(?:SRC-)?IP-ASN,`).MatchString(upper) {
			flags["asn"] = true
		}
	}
	for _, rule := range append(append([]string{}, raw.Rule...), allSubRules(raw)...) {
		scanRule(rule)
	}
	for _, payload := range preparedRules {
		for _, rule := range payload {
			scanRule(rule)
		}
	}
	for _, provider := range raw.RuleProvider {
		if payload, ok := provider["payload"].([]any); ok {
			for _, entry := range payload {
				if text, ok := entry.(string); ok {
					scanRule(text)
				}
			}
		}
	}
	for _, value := range append(append([]string{}, raw.Sniffer.ForceDomain...), raw.Sniffer.SkipDomain...) {
		if strings.HasPrefix(strings.ToLower(value), "geosite:") {
			flags["geosite"] = true
		}
	}
	for _, value := range append(append([]string{}, raw.Sniffer.SkipSrcAddress...), raw.Sniffer.SkipDstAddress...) {
		if strings.HasPrefix(strings.ToLower(value), "geoip:") {
			if raw.GeodataMode {
				flags["geoip"] = true
			} else {
				flags["mmdb"] = true
			}
		}
	}
	if raw.DNS.Enable {
		for _, policies := range []*orderedmap.OrderedMap[string, any]{raw.DNS.NameServerPolicy, raw.DNS.ProxyServerNameserverPolicy} {
			if policies == nil {
				continue
			}
			for pair := policies.Oldest(); pair != nil; pair = pair.Next() {
				if strings.HasPrefix(strings.ToLower(pair.Key), "geosite:") {
					flags["geosite"] = true
				}
			}
		}
		for _, filter := range raw.DNS.FakeIPFilter {
			scanRule(filter)
			if strings.HasPrefix(strings.ToLower(filter), "geosite:") {
				flags["geosite"] = true
			}
		}
	}
	if raw.DNS.Enable && len(raw.DNS.Fallback) != 0 && raw.DNS.FallbackFilter.GeoIP {
		if raw.GeodataMode {
			flags["geoip"] = true
		} else {
			flags["mmdb"] = true
		}
	}
	if raw.DNS.Enable && len(raw.DNS.FallbackFilter.GeoSite) != 0 {
		flags["geosite"] = true
	}
	interval := int64(0)
	if raw.GeoAutoUpdate {
		interval = int64(raw.GeoUpdateInterval) * 3600
	}
	for _, kind := range []string{"mmdb", "geoip", "geosite", "asn"} {
		if !flags[kind] {
			continue
		}
		uri := raw.GeoXUrl.Mmdb
		format := "mmdb"
		switch kind {
		case "geoip":
			uri = raw.GeoXUrl.GeoIp
			format = "dat"
		case "geosite":
			uri = raw.GeoXUrl.GeoSite
			format = "dat"
		case "asn":
			uri = raw.GeoXUrl.ASN
		}
		add(kind, format, kind, "engine-default", uri, "", "", "", interval, contract.MaxBinaryBytes)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RefID < result[j].RefID })
	return result, ""
}
