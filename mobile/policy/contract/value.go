// Package contract defines private immutable policy values. It owns no runtime,
// file or network objects, so config and mobile operations share one schema.
package contract

import "regexp"

const Version = 1
const ABIVersion = 2
const PlannerVersion = "mobile-policy-1"
const MaxControlBytes = 1024 * 1024
const MaxResultBytes = 8 * 1024 * 1024
const MaxResources = 128
const MaxTextBytes = 16 * 1024 * 1024
const MaxBinaryBytes = 128 * 1024 * 1024
const MaxTotalBytes = 256 * 1024 * 1024
const MaxGroups = 512
const MaxMembers = 4096
const MaxTotalMembers = 32768

type Resource struct {
	RefID         string `json:"refId"`
	Kind          string `json:"kind"`
	Format        string `json:"format"`
	SourceDigest  string `json:"sourceDigest"`
	ContentDigest string `json:"contentDigest"`
	ByteLength    int64  `json:"byteLength"`
	RelativePath  string `json:"relativePath"`
}

type Requirement struct {
	RefID             string `json:"refId"`
	Kind              string `json:"kind"`
	Format            string `json:"format"`
	SourceKind        string `json:"sourceKind"`
	SourceDigest      string `json:"sourceDigest"`
	SourceURI         string `json:"sourceUri,omitempty"`
	SourceHeadersJSON string `json:"sourceHeadersJson,omitempty"`
	OriginalPath      string `json:"originalPath,omitempty"`
	DownloadProxy     string `json:"downloadProxy,omitempty"`
	IntervalSeconds   int64  `json:"intervalSeconds"`
	MaxBytes          int64  `json:"maxBytes"`
}

type Member struct {
	MemberRef   string `json:"memberRef"`
	Position    int    `json:"position"`
	DisplayName string `json:"displayName"`
	Kind        string `json:"kind"`
}
type Group struct {
	GroupRef    string   `json:"groupRef"`
	Position    int      `json:"position"`
	DisplayName string   `json:"displayName"`
	Type        string   `json:"type"`
	Members     []Member `json:"members"`
}
type Adaptation struct {
	Code        string `json:"code"`
	Implemented bool   `json:"implemented"`
}
type Preference struct {
	GroupRef  string `json:"groupRef"`
	MemberRef string `json:"memberRef"`
}
type RuntimeOptions struct {
	Entry             string `json:"entry"`
	Transport         string `json:"transport"`
	DNS               bool   `json:"dns"`
	IPv6              bool   `json:"ipv6"`
	UDP               bool   `json:"udp"`
	ExplicitListeners bool   `json:"explicitListeners"`
	ResourceDownloads bool   `json:"resourceDownloads"`
}
type PlatformPolicy struct {
	Revision         string   `json:"revision"`
	AddressFamily    string   `json:"addressFamily"`
	ApplicationIDs   []string `json:"applicationIds"`
	ApplicationScope *string  `json:"applicationScope,omitempty"`
}

var applicationID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){1,15}$`)

// A missing scope is the legacy include mode, never all applications. A pointer
// retains explicitly supplied empty strings so they cannot become legacy values.
func (value PlatformPolicy) ValidApplicationScope() bool {
	if value.ApplicationIDs == nil {
		return false
	}
	if value.ApplicationScope != nil {
		switch *value.ApplicationScope {
		case "all":
			return len(value.ApplicationIDs) == 0
		case "include":
		default:
			return false
		}
	}
	if len(value.ApplicationIDs) < 1 || len(value.ApplicationIDs) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range value.ApplicationIDs {
		if len(id) > 128 || !applicationID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type IPv6Policy struct {
	Address           string `json:"address"`
	PrefixLength      int    `json:"prefixLength"`
	Route             string `json:"route"`
	RoutePrefixLength int    `json:"routePrefixLength"`
}
type TunPolicy struct {
	Address           string      `json:"address"`
	PrefixLength      int         `json:"prefixLength"`
	Route             string      `json:"route"`
	RoutePrefixLength int         `json:"routePrefixLength"`
	MTU               int         `json:"mtu"`
	IPv6              *IPv6Policy `json:"ipv6,omitempty"`
	DNSServers        []string    `json:"dnsServers,omitempty"`
}
type Platform struct {
	RuntimeOptions RuntimeOptions `json:"runtimeOptions"`
	PlatformPolicy PlatformPolicy `json:"platformPolicy"`
	TunPolicy      TunPolicy      `json:"tunPolicy"`
}
type PreparedContext struct {
	SchemaVersion          int          `json:"schemaVersion"`
	InputDigest            string       `json:"inputDigest"`
	PlannerVersion         string       `json:"plannerVersion"`
	ResourceManifestDigest string       `json:"resourceManifestDigest"`
	Resources              []Resource   `json:"resources"`
	PlatformPolicyDigest   string       `json:"platformPolicyDigest"`
	Platform               Platform     `json:"platform"`
	GroupPreferencesDigest string       `json:"groupPreferencesDigest"`
	GroupPreferences       []Preference `json:"groupPreferences"`
	CandidateDigest        string       `json:"candidateDigest"`
}
