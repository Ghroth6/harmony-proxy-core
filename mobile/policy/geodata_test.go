package policy_test

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/mobile/policy"
	"github.com/metacubex/mihomo/mobile/policy/contract"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

const geoPolicy = `ipv6: false
dns: {enable: false}
geodata-mode: true
geodata-loader: standard
rules:
 - GEOSITE,DOC,DIRECT
 - GEOIP,DOC,REJECT,no-resolve
 - MATCH,DIRECT
`

func TestOriginalPolicyUsesResourceScopedGeoMatchersWithoutGlobalCaches(t *testing.T) {
	var firstRules []C.Rule
	for _, fixture := range []struct{ domain, address string }{{"first.example", "192.0.2.1"}, {"second.example", "198.51.100.1"}} {
		root := t.TempDir()
		engine, err := policy.NewEngine(root)
		if err != nil {
			t.Fatal(err)
		}
		defer engine.Close()
		input := []byte(geoPolicy)
		plan := engine.Plan("geo-plan", input, nil)
		if plan.Category != "planned" || len(plan.Requirements) != 2 {
			t.Fatalf("geodata plan: %s/%s", plan.Category, plan.Code)
		}
		site, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "DOC", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: fixture.domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		ip, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "DOC", Cidr: []*router.CIDR{{Ip: netip.MustParseAddr(fixture.address).AsSlice(), Prefix: 24}}}}})
		if err != nil {
			t.Fatal(err)
		}
		resources := []contract.Resource{}
		for _, requirement := range plan.Requirements {
			payload := site
			if requirement.Kind == "geoip" {
				payload = ip
			}
			resources = append(resources, savePublicResource(t, root, requirement, payload))
		}
		prepared, err := contract.Seal(plan.InputDigest, resources, publicPlatform(), nil)
		if err != nil {
			t.Fatal(err)
		}
		baseline := engine.ResourceAcquireCount()
		candidate, err := engine.BuildCandidate(input, prepared)
		if err != nil {
			t.Fatalf("actual prepared geodata candidate: %s", err)
		}
		defer func() {
			if err := candidate.Discard(context.Background()); err != nil {
				t.Fatal(err)
			}
		}()
		if match, _ := candidate.Rules[0].Match(&C.Metadata{Host: "a." + fixture.domain}, C.RuleMatchHelper{}); !match {
			t.Fatal("source geosite bytes were not compiled")
		}
		if match, _ := candidate.Rules[1].Match(&C.Metadata{DstIP: netip.MustParseAddr(fixture.address)}, C.RuleMatchHelper{}); !match {
			t.Fatal("source geoip bytes were not compiled")
		}
		if firstRules == nil {
			firstRules = candidate.Rules
		} else {
			if match, _ := firstRules[0].Match(&C.Metadata{Host: "a.second.example"}, C.RuleMatchHelper{}); match {
				t.Fatal("new manifest replaced an older candidate's same-country matcher")
			}
			if match, _ := candidate.Rules[0].Match(&C.Metadata{Host: "a.first.example"}, C.RuleMatchHelper{}); match {
				t.Fatal("global country cache leaked into a new manifest")
			}
		}
		if engine.ResourceAcquireCount() != baseline {
			t.Fatal("geodata preparation made an acquisition")
		}
	}
}

func TestOriginalPolicyPlanRejectsMalformedBinaryInsteadOfMetadataOnlyReady(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['GEOSITE,DOC,DIRECT', 'MATCH,DIRECT']\n")
	plan := engine.Plan("bad-geodata-plan", input, nil)
	resource := savePublicResource(t, root, plan.Requirements[0], []byte{0xff, 0xff})
	actual := engine.Plan("bad-geodata-fixed", input, []contract.Resource{resource})
	if actual.Category == "planned" || actual.ResourcesComplete || actual.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" {
		t.Fatal("a hash alone must not mark invalid DAT as ready")
	}
}

func publicCountryMMDB(t *testing.T) []byte {
	t.Helper()
	// Both halves of an IPv4 tree point at the single string record "zz".
	// This is a synthetic sing-geoip DB, with intentionally empty descriptive
	// metadata. None of these bytes is taken from a downloaded database.
	return publicEmbeddedCountryMMDB(t, []byte{0x42, 'z', 'z'}, 0)
}

func publicEmbeddedCountryMMDB(t *testing.T, record []byte, offset byte) []byte {
	t.Helper()
	data := publicMMDBEnvelope([]byte{0, 0, 17 + offset, 0, 0, 17 + offset}, 1, "sing-geoip", record)
	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		t.Fatal("synthetic database must be readable by the pinned original reader:", err)
	}
	defer reader.Close()
	var country string
	if err = reader.Lookup(netip.MustParseAddr("192.0.2.1").AsSlice(), &country); err != nil || country != "zz" {
		t.Fatal("synthetic database must contain its actual country record")
	}
	return data
}

func publicMMDBEnvelope(tree []byte, nodeCount byte, databaseType string, record []byte) []byte {
	data := append([]byte(nil), tree...)
	data = append(data, make([]byte, 16)...)
	data = append(data, record...)
	data = append(data, []byte("\xab\xcd\xefMaxMind.com")...)
	data = append(data, 0xe7)
	str := func(value string) { data = append(data, byte(0x40|len(value))); data = append(data, value...) }
	number := func(key string, value byte) { str(key); data = append(data, 0xc1, value) }
	number("node_count", nodeCount)
	number("record_size", 24)
	number("ip_version", 4)
	number("binary_format_major_version", 2)
	number("binary_format_minor_version", 0)
	str("database_type")
	str(databaseType)
	str("description")
	data = append(data, 0xe0)
	return data
}

func TestOriginalMMDBReachableSharedFieldMatchesWithoutRewritingBytes(t *testing.T) {
	// A tree entry may target a value embedded in a larger unindexed record;
	// another record may in turn point at that same value. The original pinned
	// reader independently resolves both layouts to the actual country.
	for _, record := range []struct {
		name   string
		data   []byte
		offset byte
	}{
		{"embedded-field", []byte{0xe1, 0x41, 'k', 0x42, 'z', 'z'}, 3},
		{"shared-field-pointer", []byte{0xe1, 0x41, 'k', 0x42, 'z', 'z', 0x20, 3}, 6},
	} {
		t.Run(record.name, func(t *testing.T) {
			root := t.TempDir()
			engine, err := policy.NewEngine(root)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['GEOIP,ZZ,REJECT,no-resolve', 'MATCH,DIRECT']\n")
			plan := engine.Plan("shared-country-plan", input, nil)
			body := publicEmbeddedCountryMMDB(t, record.data, record.offset)
			resource := savePublicResource(t, root, plan.Requirements[0], body)
			baseline := engine.ResourceAcquireCount()
			ready := engine.Plan("shared-country-ready", input, []contract.Resource{resource})
			if ready.Category != "planned" || !ready.ResourcesComplete {
				t.Fatalf("readable embedded/shared country must be ready: %s/%s", ready.Category, ready.Code)
			}
			prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, publicPlatform(), nil)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := engine.BuildCandidate(input, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if match, target := candidate.Rules[0].Match(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, C.RuleMatchHelper{}); !match || target != "REJECT" {
				t.Fatal("reachable original field was not compiled into the original GEOIP rule")
			}
			if err = candidate.Discard(context.Background()); err != nil {
				t.Fatal(err)
			}
			if resource.ContentDigest != contract.Digest(body) || engine.ResourceAcquireCount() != baseline {
				t.Fatal("compatible validation changed the original resource identity or acquired bytes")
			}
		})
	}
}

func TestOriginalMMDBWithEmptyDescriptionKeepsActualCountryAndRejectsMalformedData(t *testing.T) {
	root := t.TempDir()
	engine, err := policy.NewEngine(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['GEOIP,ZZ,REJECT,no-resolve', 'MATCH,DIRECT']\n")
	plan := engine.Plan("mmdb-original-plan", input, nil)
	if plan.Category != "planned" || len(plan.Requirements) != 1 || plan.Requirements[0].Kind != "mmdb" {
		t.Fatal("original country rule must require its actual database")
	}
	body := publicCountryMMDB(t)
	resource := savePublicResource(t, root, plan.Requirements[0], body)
	baseline := engine.ResourceAcquireCount()
	ready := engine.Plan("mmdb-original-ready", input, []contract.Resource{resource})
	if ready.Category != "planned" || !ready.ResourcesComplete {
		t.Fatalf("non-routing description must not reject a readable country database: %s/%s", ready.Category, ready.Code)
	}
	prepared, err := contract.Seal(plan.InputDigest, []contract.Resource{resource}, publicPlatform(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := engine.BuildCandidate(input, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if matched, target := candidate.Rules[0].Match(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, C.RuleMatchHelper{}); !matched || target != "REJECT" {
		t.Fatal("original rule must use the database's actual country, without altering its bytes")
	}
	if err = candidate.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	broken := append([]byte(nil), body...)
	broken[22] = 0xff // malformed actual data record, with intact metadata/tree.
	bad := savePublicResource(t, root, plan.Requirements[0], broken)
	invalid := engine.Plan("mmdb-original-bad-data", input, []contract.Resource{bad})
	if invalid.Category != "invalid" || invalid.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" || invalid.ResourcesComplete || engine.ResourceAcquireCount() != baseline {
		t.Fatal("descriptive metadata compatibility must not weaken actual data/tree verification or fetch resources")
	}
}

func TestOriginalMMDBHasNoExtraFileSizeQuota(t *testing.T) {
	base := publicCountryMMDB(t)
	marker := bytes.LastIndex(base, []byte("\xab\xcd\xefMaxMind.com"))
	// Unindexed data need not be decoded. Keep the original tree and record,
	// padding the data section past the former 128 MiB admission quota.
	body := make([]byte, (128<<20)+len(base))
	copy(body, base[:marker])
	copy(body[len(body)-(len(base)-marker):], base[marker:])
	for _, open := range []struct {
		name string
		read func([]byte) (*maxminddb.Reader, error)
	}{
		{"upstream", maxminddb.FromBytes},
		{"prepared", func(b []byte) (*maxminddb.Reader, error) {
			r, err := mmdb.NewPreparedIP(b)
			if err != nil {
				return nil, err
			}
			return r.Reader, nil
		}},
	} {
		t.Run(open.name, func(t *testing.T) {
			r, err := open.read(body)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var country string
			if err = r.Lookup(netip.MustParseAddr("192.0.2.1").AsSlice(), &country); err != nil || country != "zz" {
				t.Fatalf("original record lost: %q / %v", country, err)
			}
		})
	}
}

func TestOriginalMMDBRejectsCorruptReachableGraphAndBoundedExpansion(t *testing.T) {
	base := publicEmbeddedCountryMMDB(t, []byte{0xe1, 0x41, 'k', 0x42, 'z', 'z', 0x20, 3}, 6)
	changed := func(index int, value byte) []byte {
		result := append([]byte(nil), base...)
		result[index] = value
		return result
	}
	deepTree := make([]byte, 34*6)
	for index := 0; index < 34; index++ {
		deepTree[index*6+2], deepTree[index*6+5] = byte(index+1), 50
	}
	deepTree[33*6+2] = 50
	deep := publicMMDBEnvelope(deepTree, 34, "sing-geoip", []byte{0x42, 'z', 'z'})
	// Each small array references its predecessor twice. An unrelated field
	// points at that DAG: a raw-byte cap cannot bound its expanded work. The
	// original typed country reader can still resolve the actual country.
	dag := []byte{0x42, 'z', 'z'}
	previous := byte(0)
	for index := 0; index < 18; index++ {
		position := byte(len(dag))
		dag = append(dag, 0x02, 0x04, 0x20, previous, 0x20, previous)
		previous = position
	}
	rootOffset := byte(len(dag))
	dag = append(dag, 0xe2, 0x47)
	dag = append(dag, "country"...)
	dag = append(dag, 0xe1, 0x48)
	dag = append(dag, "iso_code"...)
	dag = append(dag, 0x42, 'z', 'z', 0x47)
	dag = append(dag, "ignored"...)
	dag = append(dag, 0x20, previous)
	expanding := publicMMDBEnvelope([]byte{0, 0, 17 + rootOffset, 0, 0, 17 + rootOffset}, 1, "GeoLite2-Country", dag)
	reader, err := maxminddb.FromBytes(expanding)
	if err != nil {
		t.Fatal(err)
	}
	var country struct {
		Country struct {
			Code string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err = reader.Lookup(netip.MustParseAddr("192.0.2.1").AsSlice(), &country); err != nil || country.Country.Code != "zz" {
		t.Fatal("expansion fixture must have a readable country", err)
	}
	_ = reader.Close()
	metadataEnd := bytes.LastIndex(base, []byte("\xab\xcd\xefMaxMind.com")) + 14
	badMetadata := append(append([]byte(nil), base[:metadataEnd]...), 0xfe, 0xff, 0xff)
	countOffset := bytes.Index(base, []byte("node_count")) + len("node_count")
	overflowCount := append(append([]byte(nil), base[:countOffset]...), 0x08, 0x02, 0x20, 0, 0, 0, 0, 0, 0, 0)
	overflowCount = append(overflowCount, base[countOffset+2:]...)
	sizeOffset := bytes.Index(overflowCount, []byte("record_size")) + len("record_size")
	overflowCount[sizeOffset+1] = 32
	for _, fixture := range []struct {
		name string
		body []byte
	}{
		{"tree-cycle", changed(2, 0)},
		{"tree-depth", deep},
		{"reserved-tree-pointer", changed(2, 2)},
		{"separator", changed(6, 1)},
		{"record-type", changed(25, 0xff)},
		{"data-pointer-cycle", changed(29, 6)},
		{"data-pointer-bounds", changed(29, 254)},
		{"metadata-container-allocation", badMetadata},
		{"metadata-tree-size-overflow", overflowCount},
		{"shared-data-expansion", expanding},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := t.TempDir()
			engine, err := policy.NewEngine(root)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			input := []byte("ipv6: false\ndns: {enable: false}\nrules: ['GEOIP,ZZ,REJECT,no-resolve', 'MATCH,DIRECT']\n")
			plan := engine.Plan("bounded-mmdb-plan", input, nil)
			resource := savePublicResource(t, root, plan.Requirements[0], fixture.body)
			baseline := engine.ResourceAcquireCount()
			invalid := engine.Plan("bounded-mmdb-invalid", input, []contract.Resource{resource})
			if invalid.Category != "invalid" || invalid.Code != "POLICY_RESOURCE_PAYLOAD_INVALID" || invalid.ResourcesComplete || engine.ResourceAcquireCount() != baseline {
				t.Fatal("untrusted reachable MMDB graph must fail bounded and without acquisitions")
			}
		})
	}
}
