package mmdb

import "github.com/oschwald/maxminddb-golang"

// Prepared readers use the same opening and type dispatch as IPInstance and
// ASNInstance. Only ownership differs: no global sync.Once or fatal logging;
// each candidate closes its own reader. Records are decoded on lookup.
func NewPreparedIP(buffer []byte) (*IPReader, error) {
	r, err := maxminddb.FromBytes(buffer)
	if err != nil {
		return nil, err
	}
	reader := &IPReader{Reader: r}
	switch r.Metadata.DatabaseType {
	case "sing-geoip":
		reader.databaseType = typeSing
	case "Meta-geoip0":
		reader.databaseType = typeMetaV0
	default:
		reader.databaseType = typeMaxmind
	}
	return reader, nil
}

func NewPreparedASN(buffer []byte) (*ASNReader, error) {
	r, err := maxminddb.FromBytes(buffer)
	if err != nil {
		return nil, err
	}
	return &ASNReader{Reader: r}, nil
}
