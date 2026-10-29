package mmdb

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

// Synthetic MMDB encoding for public compatibility cases; no downloaded data.
func mmdbValue(kind byte, size int) []byte {
	prefix := kind << 5
	var extension []byte
	if kind > 7 {
		prefix = 0
		extension = []byte{kind - 7}
	}
	var length []byte
	switch {
	case size < 29:
		prefix |= byte(size)
	case size < 285:
		prefix |= 29
		length = []byte{byte(size - 29)}
	case size < 65821:
		prefix |= 30
		n := size - 285
		length = []byte{byte(n >> 8), byte(n)}
	default:
		prefix |= 31
		n := size - 65821
		length = []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{prefix}, extension...), length...)
}

func mmdbString(value string) []byte { return append(mmdbValue(2, len(value)), value...) }

func mmdbRecord(kind string, record, metadataExtra []byte) []byte {
	body := append([]byte{0, 0, 17, 0, 0, 17}, make([]byte, 16)...)
	body = append(body, record...)
	body = append(body, []byte("\xab\xcd\xefMaxMind.com")...)
	fields := 6
	if metadataExtra != nil {
		fields++
	}
	body = append(body, mmdbValue(7, fields)...)
	for _, item := range []struct {
		name  string
		value byte
	}{
		{"node_count", 1}, {"record_size", 24}, {"ip_version", 4},
		{"binary_format_major_version", 2}, {"binary_format_minor_version", 0},
	} {
		body = append(body, mmdbString(item.name)...)
		body = append(body, 0xc1, item.value)
	}
	body = append(body, mmdbString("database_type")...)
	body = append(body, mmdbString(kind)...)
	return append(body, metadataExtra...)
}

func countryRecord(extra []byte) []byte {
	body := []byte{0xe2}
	body = append(body, mmdbString("country")...)
	body = append(body, 0xe1)
	body = append(body, mmdbString("iso_code")...)
	body = append(body, mmdbString("zz")...)
	body = append(body, mmdbString("ignored")...)
	return append(body, extra...)
}

func TestPreparedCountryUsesUpstreamFieldsWithoutBudgets(t *testing.T) {
	deep := mmdbString("ignored")
	for i := 0; i < 80; i++ {
		deep = append(mmdbValue(11, 1), deep...)
	}
	largeContainer := mmdbValue(11, 4097)
	for i := 0; i < 4097; i++ {
		largeContainer = append(largeContainer, mmdbString("x")...)
	}
	metadata := append(mmdbString("description"), 0xe1)
	metadata = append(metadata, mmdbString("en")...)
	metadata = append(metadata, mmdbString(strings.Repeat("x", 129<<10))...)
	visits := append(mmdbString("languages"), mmdbValue(11, 9000)...)
	for i := 0; i < 9000; i++ {
		visits = append(visits, mmdbString("en")...)
	}
	for _, test := range []struct {
		name, kind      string
		extra, metadata []byte
	}{
		{"record-depth", "GeoLite2-Country", deep, nil},
		{"record-container", "GeoLite2-Country", largeContainer, nil},
		{"record-expanded-bytes", "GeoLite2-Country", mmdbString(strings.Repeat("x", (1<<20)+1)), nil},
		{"metadata-bytes", "GeoLite2-Country", mmdbString("x"), metadata},
		{"metadata-visits", "GeoLite2-Country", mmdbString("x"), visits},
		{"upstream-default-type", "Custom-Country", mmdbString("x"), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := mmdbRecord(test.kind, countryRecord(test.extra), test.metadata)
			original, err := maxminddb.FromBytes(body)
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			want := (IPReader{Reader: original, databaseType: typeMaxmind}).LookupCode(net.ParseIP("192.0.2.1"))
			if len(want) != 1 || want[0] != "zz" {
				t.Fatal("invalid fixture", want)
			}
			prepared, err := NewPreparedIP(body)
			if err != nil {
				t.Fatal("upstream-readable country rejected:", err)
			}
			defer prepared.Close()
			got := prepared.LookupCode(net.ParseIP("192.0.2.1"))
			if len(got) != 1 || got[0] != want[0] {
				t.Fatal("country result changed", got)
			}
		})
	}
}

func TestPreparedASNUsesUpstreamLargeRecordAndIndependentOwnership(t *testing.T) {
	organization := strings.Repeat("x", (1<<20)+1)
	record := append([]byte{0xe2}, mmdbString("autonomous_system_number")...)
	record = append(record, 0xc1, 42)
	record = append(record, mmdbString("autonomous_system_organization")...)
	record = append(record, mmdbString(organization)...)
	body := mmdbRecord("GeoLite2-ASN", record, nil)
	original, err := maxminddb.FromBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	wantNumber, wantName := (ASNReader{Reader: original}).LookupASN(net.ParseIP("192.0.2.1"))
	first, err := NewPreparedASN(body)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPreparedASN(body)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	gotNumber, gotName := second.LookupASN(net.ParseIP("192.0.2.1"))
	if gotNumber != wantNumber || gotName != wantName || gotNumber != "42" || gotName != organization {
		t.Fatal("large ASN field or candidate ownership changed")
	}
}

func TestPreparedMMDBKeepsUpstreamOpenAndLookupErrorBoundary(t *testing.T) {
	body := mmdbRecord("sing-geoip", []byte{0x20, 0}, nil) // self pointer: open succeeds, lookup hits upstream depth limit.
	for _, open := range []struct {
		name string
		read func([]byte) (*maxminddb.Reader, error)
	}{
		{"upstream", maxminddb.FromBytes},
		{"prepared", func(b []byte) (*maxminddb.Reader, error) {
			r, err := NewPreparedIP(b)
			if err != nil {
				return nil, err
			}
			return r.Reader, nil
		}},
	} {
		t.Run(open.name, func(t *testing.T) {
			r, err := open.read(body)
			if err != nil {
				t.Fatal("record must be decoded at lookup", err)
			}
			defer r.Close()
			var value string
			if err = r.Lookup(net.ParseIP("192.0.2.1"), &value); err == nil {
				t.Fatal("upstream corrupt pointer error disappeared")
			}
			for _, invalid := range [][]byte{[]byte("not MMDB"), body[:bytes.LastIndex(body, []byte("\xab\xcd\xefMaxMind.com"))+15]} {
				if r, err := open.read(invalid); err == nil {
					r.Close()
					t.Fatal("malformed metadata accepted")
				}
			}
		})
	}
}
