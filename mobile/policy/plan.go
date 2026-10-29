package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/orderedmap"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
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
	return e.plan(operationID, input, available, nil, nil)
}

func (e *Engine) plan(operationID string, input []byte, available []PreparedResource, verified *map[string]fixedResource, resolvedMembers map[string][]string) (receipt PlanReceipt) {
	receipt = PlanReceipt{SchemaVersion: contract.Version, OperationID: operationID, InputDigest: digest(input), PlannerVersion: contract.PlannerVersion,
		Category: "failure", Code: "POLICY_FAILURE", Requirements: []contract.Requirement{}, Groups: []contract.Group{}, Adaptations: []contract.Adaptation{}, CoreIdentity: validation.Identity()}
	defer func() {
		if recover() != nil {
			receipt.Category = "failure"
			receipt.Code = "POLICY_FAILURE"
			receipt.ResourcesComplete = false
		}
	}()
	if !safeOperation(operationID) || len(input) > contract.MaxControlBytes {
		receipt.Code = "POLICY_REQUEST_BOUNDS"
		return
	}
	if !e.available() {
		receipt.Code = "POLICY_RESOURCE_OWNER_RETIRED"
		return
	}
	raw, code := decodePolicy(input)
	if code != "" {
		receipt.Category = "invalid"
		receipt.Code = code
		return
	}
	receipt.GeneralIPv6, receipt.DNSEnabled, receipt.DNSIPv6 = raw.IPv6, raw.DNS.Enable, raw.DNS.IPv6
	receipt.StoreSelected, receipt.StoreFakeIP = raw.Profile.StoreSelected, raw.Profile.StoreFakeIP
	for _, provider := range raw.ProxyProvider {
		if provider["type"] == "http" {
			receipt.RuntimeDownloads = true
		}
	}
	groups, code := e.planGroups(raw, receipt.InputDigest, resolvedMembers)
	if code != "" {
		receipt.Category = "invalid"
		if strings.HasSuffix(code, "NOT_IMPLEMENTED") || code == "PROXY_TYPE_UNSUPPORTED" {
			receipt.Category = "unsupported"
		}
		if code == "PREPARATION_NETWORK_FORBIDDEN" || code == "POLICY_CLEANUP_FAILED" || code == "POLICY_CONSTRUCTION_FAILED" {
			receipt.Category = "failure"
		}
		receipt.Code = code
		return
	}
	receipt.Groups = groups
	requirements, code := planRequirements(raw, receipt.InputDigest)
	if code != "" {
		receipt.Category = "unsupported"
		receipt.Code = code
		return
	}
	receipt.Requirements = requirements
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
		requirements, code = planRequirements(raw, receipt.InputDigest, providerRules)
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

func decodePolicy(input []byte) (*config.RawConfig, string) {
	// Reuse upstream decryption and YAML semantics, including aliases, merge
	// keys and ignored extension fields. Do not impose another schema here.
	raw := config.DefaultRawConfig()
	// Mobile defaults must not inherit a previously published mutable global.
	raw.GeodataMode = false
	input, err := age.DecryptBytes(input)
	if err != nil || yaml.Unmarshal(input, raw) != nil {
		return nil, "POLICY_FORMAT_INVALID"
	}
	return raw, ""
}

// Planning and runtime use the same real upstream proxy graph. The candidate
// owns all constructed adapters/health owners and its network fence stays shut.
func (e *Engine) planGroups(raw *config.RawConfig, inputDigest string, resolvedMembers map[string][]string) (result []contract.Group, code string) {
	candidate, err := config.BuildMobileProxyCandidate(raw)
	if candidate != nil {
		defer func() {
			if err := candidate.Discard(context.Background()); err != nil {
				e.retainCandidate(candidate, err)
				result = nil
				code = "POLICY_CLEANUP_FAILED"
			}
		}()
	}
	if err != nil {
		var detail *config.MobileValidationError
		if errors.As(err, &detail) {
			return nil, detail.Code
		}
		return nil, "POLICY_PROXY_OR_GROUP_INVALID"
	}
	names := map[string]string{}
	for name := range candidate.Proxies {
		names[name] = "builtin"
	}
	for _, node := range raw.Proxy {
		var original struct {
			Name string `proxy:"name"`
		}
		decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
		if decoder.Decode(node, &original) != nil {
			return nil, "PROXY_INVALID"
		}
		names[original.Name] = "node"
	}
	for _, provider := range candidate.Providers {
		for _, proxy := range provider.Proxies() {
			if names[proxy.Name()] == "" {
				names[proxy.Name()] = "node"
			}
		}
	}
	for _, group := range raw.ProxyGroup {
		name, _ := group["name"].(string)
		names[name] = "group"
	}
	result = []contract.Group{}
	for position, mapping := range raw.ProxyGroup {
		name, _ := mapping["name"].(string)
		kind, _ := mapping["type"].(string)
		group, ok := candidate.Proxies[name].Adapter().(interface{ GetProxies(bool) []C.Proxy })
		if !ok {
			return nil, "POLICY_GROUP_INVALID"
		}
		members := group.GetProxies(false)
		item := contract.Group{GroupRef: digest([]byte(inputDigest + ":group:" + strconv.Itoa(position+1))), Position: position + 1, DisplayName: safeName(name), Type: kind, Members: []contract.Member{}}
		for index, member := range members {
			item.Members = append(item.Members, contract.Member{MemberRef: digest([]byte(inputDigest + ":group:" + strconv.Itoa(position+1) + ":member:" + strconv.Itoa(index+1))), Position: index + 1, DisplayName: safeName(member.Name()), Kind: names[member.Name()]})
			if resolvedMembers != nil {
				resolvedMembers[item.GroupRef] = append(resolvedMembers[item.GroupRef], member.Name())
			}
		}
		result = append(result, item)
	}
	return result, ""
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

func planRequirements(raw *config.RawConfig, inputDigest string, preparedRules ...[]string) ([]contract.Requirement, string) {
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
		kind, _ := value["type"].(string)
		behavior, _ := value["behavior"].(string)
		format, _ := value["format"].(string)
		if format == "" {
			format = "yaml"
		}
		if behavior != "classical" && behavior != "domain" && behavior != "ipcidr" {
			return nil, "POLICY_RESOURCE_BEHAVIOR_UNSUPPORTED"
		}
		if format != "yaml" && format != "text" && format != "mrs" || format == "mrs" && behavior == "classical" {
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
		maxBytes := int64(contract.MaxResourceBytes)
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
		add(kind, format, kind, "engine-default", uri, "", "", "", interval, contract.MaxResourceBytes)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RefID < result[j].RefID })
	return result, ""
}
