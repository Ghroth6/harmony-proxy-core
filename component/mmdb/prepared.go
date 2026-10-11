package mmdb

import (
	"errors"

	"github.com/oschwald/maxminddb-golang"
)

// Prepared readers own verified bytes. They never enter global sync.Once,
// reload paths, downloads or fatal logging, and are closed by the candidate.
func NewPreparedIP(buffer []byte) (*IPReader, error) {
	r, err := maxminddb.FromBytes(buffer)
	if err != nil {
		return nil, err
	}
	if err = r.Verify(); err != nil {
		_ = r.Close()
		return nil, err
	}
	reader := &IPReader{Reader: r}
	switch r.Metadata.DatabaseType {
	case "sing-geoip":
		reader.databaseType = typeSing
	case "Meta-geoip0":
		reader.databaseType = typeMetaV0
	case "GeoLite2-Country", "GeoIP2-Country", "DBIP-Country-Lite (compat=GeoLite2-Country)":
		reader.databaseType = typeMaxmind
	default:
		_ = r.Close()
		return nil, errors.New("unsupported IP database type")
	}
	return reader, nil
}

func NewPreparedASN(buffer []byte) (*ASNReader, error) {
	r, err := maxminddb.FromBytes(buffer)
	if err != nil {
		return nil, err
	}
	if err = r.Verify(); err != nil {
		_ = r.Close()
		return nil, err
	}
	switch r.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)", "ipinfo generic_asn_free.mmdb":
		return &ASNReader{Reader: r}, nil
	default:
		_ = r.Close()
		return nil, errors.New("unsupported ASN database type")
	}
}
